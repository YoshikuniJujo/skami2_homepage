{-# LANGUAGE OverloadedStrings, PackageImports, TupleSections #-}

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first, second)
import "monads-tf" Control.Monad.State (
	MonadIO, liftIO, forever, void, StateT(..), runStateT )
import Control.Concurrent (forkIO)
import Data.Bool (bool)
import Data.Maybe (fromMaybe, fromJust, listToMaybe)
import Data.Char (isSpace)
import Data.HandleLike (hlClose, HandleMonad)
import Data.Pipe (Pipe, runPipe, (=$=))
import Data.Pipe.List (toList)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Time (getZonedTime)
import System.IO (Handle, openBinaryFile, IOMode(..))
import Network (PortID(..), listenOn, accept)
import Network.PeyoTLS.Server (
	CipherSuite, PeyotlsM, PeyotlsHandle, TlsHandle, run, open)
import Network.PeyoTLS.ReadFile (readKey, readCertificateChain)
import Network.TigHTTP.Server (getRequest, putResponse, response, requestBody)
import Network.TigHTTP.Types (
	Request(..), Path(..), Get(..), Post(..),
	Response(..), ContentType(..), Type(..), Subtype(..), SetCookie(..),
	StatusCode(..), Parameter(..) )
import "crypto-random" Crypto.Random (
	SystemRNG, createEntropyPool, cprgCreate, cprgFork )
import Text.Template (template)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

import UUID4 (UUID4, newGen, uuid4IO)
-- import MakeHash
import MailTo
import UserGroup
import URLEncode

import qualified Account as Acc

type Body = Pipe () BS.ByteString (HandleMonad PeyotlsHandle) ()
type Pairs = [(BS.ByteString, BS.ByteString)]
type RndGen = IORef SystemRNG
type UTable = IORef [(UUID4, BS.ByteString)]
type St = (UTable, RndGen)

cipherSuites :: [CipherSuite]
cipherSuites = [
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA"
	]

main :: IO ()
main = do
	(k, c, g0, ut, rg) <- (,,,,)
		<$> readKey "2015_skami2.key"
		<*> readCertificateChain ["2015_skami2.cert", "2015_skami2.int"]
		<*> (cprgCreate <$> createEntropyPool :: IO SystemRNG)
		<*> newIORef []
		<*> (newIORef =<< newGen)
	soc <- listenOn $ PortNumber 443
	setGroup "hummingbird"
	setUser "hummingbird"
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- io $ accept soc
		g <- StateT $ return . cprgFork
		void . io . forkIO . (`run` g) $ do
			t <- open h cipherSuites [(k, c)] Nothing
			r <- getRequest t
			resp r ut t rg
			hlClose t

instance Eq Path where Path p1 == Path p2 = p1 == p2

path :: Request PeyotlsHandle -> (Path, Maybe Pairs)
path (RequestGet p@(Path b) _ _) = case span (/= '?') $ unp b of
	(pt, '?' : pr) -> (Path $ pck pt, Just . pairs $ pck pr)
	_ -> (p, Nothing)
path (RequestPost p _ _) = (p, Nothing)
path (RequestRaw _ p _ _) = (p, Nothing)

getContentType :: Request h -> Maybe ContentType
getContentType (RequestPost _ _ p) = postContentType p
getContentType _ = Nothing

resp :: Request PeyotlsHandle -> UTable -> PeyotlsHandle -> RndGen -> PeyotlsM ()
resp r ut t rg = do
	liftIO . print $ getContentType r
	(pr_, mimg) <- case getContentType r of
		Just (ContentType (TypeRaw "multipart") (SubtypeRaw "form-data") [
			ParameterRaw "boundary" bnd ]) -> do
				cnt <- getBodyContents $ requestBody r
				return ([], Just $ getUploaded bnd cnt)
		_ -> (, Nothing) <$> getPairs (requestBody r)
	let	(pt, mpr) = path r
		pr = fromMaybe pr_ mpr
		c = case r of
			RequestGet _ _ g -> getCookie g
			RequestPost _ _ pst -> postCookie pst
			_ -> []
		s = (ut, rg)
		mh = lookup (not $ null pr, pt) pages
	liftIO $ print mimg
	liftIO $ print pr
	liftIO $ print c
	mu <- (User <$>) <$> io (getUser ut $ getUUID4 c)
	conn <- liftIO Acc.open
	case mh of
		Just (Static ct pg) -> showFile t ct pg
		Just (Dynamic f) -> f t conn mu pr s
		_	| "/requests/" `BS.isPrefixOf` (\(Path p) -> p) pt ->
				(showPage t html =<<) . io $ do
					tt <- BS.readFile
						"static/requests/template.html"
					let Path p = pt
					fromJust <$> template
						(reqLookup p)
						(reqValues $ BS.drop 10 $
							(\(Path pp) -> pp) pt)
						tt
			| "/images/" `BS.isPrefixOf` (\(Path p) -> p) pt -> do
				let Path p = pt
				showFile t png . ("static/" ++) $ BSC.unpack p
			| pt == Path "/requests" -> do
				u <- io $ uuid4IO rg
				let pg = "static/images/" ++ show u ++ ".png"
				io $ print pg
				let mreq = lookup "name" =<<
					snd . snd . head . fst <$> mimg
				io $ print mreq
				io $ do	h <- openBinaryFile pg WriteMode
					BS.hPut h $ maybe "" snd mimg
				io $ maybe (return ())
					(Acc.insertImage . BSC.pack $ show u) mreq
				showFile t html "static/requests/hello.html"
			| otherwise -> do
				io . putStrLn $ "badbadbad:" ++ show pt
				putResponse t (response' $
					LBS.fromChunks ["404 File not found"]) {
					responseStatusCode = NotFound,
					responseContentType = text,
					responseOthers = hsts }

getUploaded :: BS.ByteString -> BS.ByteString ->
	([(BS.ByteString, (BS.ByteString, [(BS.ByteString, BS.ByteString)]))],
		BS.ByteString)
getUploaded b cnt =
	first (map $ second (withAttributes . BSC.dropWhile isSpace . BSC.tail) . BSC.break (== ':'))
		. spanEmptyLine $ fromMultipart ("--" `BS.append` b) cnt

spanEmptyLine :: BS.ByteString -> ([BS.ByteString], BS.ByteString)
spanEmptyLine bs = case popLine bs of
	("", r) -> ([], r)
	(l, r) -> (l :) `first` spanEmptyLine r

withAttributes :: BS.ByteString -> (BS.ByteString, [(BS.ByteString, BS.ByteString)])
withAttributes bs = attributes `second` BSC.break (== ';') bs

attributes :: BS.ByteString -> [(BS.ByteString, BS.ByteString)]
attributes bs
	| BS.null bs = []
	| otherwise = let (p, bs') = BSC.break (== ';') $ BSC.tail bs in
		(BSC.takeWhile (/= '"') . BSC.tail . BSC.dropWhile (/= '"'))
				`second`
				BSC.break (== '=') (BSC.dropWhile isSpace p)
			: attributes bs'

popLine :: BS.ByteString -> (BS.ByteString, BS.ByteString)
popLine bs = BSC.drop 2 `second` BSC.break (== '\r') bs

fromMultipart :: BS.ByteString -> BS.ByteString -> BS.ByteString
fromMultipart b cnt
	| BS.isPrefixOf (b `BS.append` "\r\n") cnt =
		takeMultipart ("\r\n" `BS.append` b `BS.append` "--") $
			BS.drop (BS.length b + 2) cnt
	| otherwise = fromMultipart b $ BS.tail cnt

takeMultipart :: BS.ByteString -> BS.ByteString -> BS.ByteString
takeMultipart b cnt
	| BS.isPrefixOf (b `BS.append` "\r\n") cnt = BS.empty
	| otherwise = BS.cons (BS.head cnt) $ takeMultipart b (BS.tail cnt)

getBodyContents :: Body -> PeyotlsM BS.ByteString
getBodyContents b = maybe "" BS.concat <$> runPipe (b =$= toList)

reqLookup :: BS.ByteString -> BS.ByteString -> [BS.ByteString]
reqLookup i "REQ_ID" = [BS.drop 10 i]
reqLookup _ _ = []

reqValues :: BS.ByteString -> BS.ByteString -> IO [BS.ByteString]
reqValues i "DESC" = do
	print i
	(: []) . decode . fromJust <$> Acc.getReqDescription i
reqValues i "IMAGE_ID" = map (`BS.append` ".png") <$> Acc.getImages i
reqValues _ _ = return []

response' :: LBS.ByteString -> Response Pipe PeyotlsHandle
response' = response

pages :: [((Bool, Path), Page)]
pages = [
	((False, Path "/"), Dynamic index),
	((True, Path "/"), Dynamic index),
	((False, Path "/login"), Dynamic index),
	((True, Path "/login"), Dynamic login),
	((False, Path "/logout"), logout),
	((False, Path "/signup"), Static html "static/signup.html"),
	((True, Path "/signup"), signup),
	((False, Path "/activate"), Static html "static/to_activate.html"),
	((True, Path "/activate"), activate),
	((False, Path "/robots.txt"), Static text "static/robots.txt"),
	((False, Path "/favicon.ico"), Static ico "static/favicon.ico") ]

html, text, ico, png :: ContentType
html = ContentType Text Html []
text = ContentType Text Plain []
ico = ContentType (TypeRaw "image") (SubtypeRaw "vnd.microsoft.icon") []
png = ContentType (TypeRaw "image") (SubtypeRaw "png") []

data Page
	= Static { contentType :: ContentType, static :: FilePath }
	| Dynamic {
		dynamic :: PeyotlsHandle -> Acc.Connection ->
			Maybe User -> Pairs -> St -> PeyotlsM ()
		}

data User = User BS.ByteString deriving Show

index :: PeyotlsHandle ->
	Acc.Connection -> Maybe User -> Pairs -> St -> PeyotlsM ()
index t conn (Just u@(User un)) ps _ = do
	io . putStrLn $ "index: " ++ show ps
	io $ case lookup "request" ps of
		Just r -> Acc.insertRequest conn (Acc.UserName un) r
		_ -> return ()
	showPage t html =<< io . setUName u =<<
		io (BS.readFile "static/i_know.html")
index t _ _ _ _ = showFile t html "static/index.html"

getPairs :: Body -> PeyotlsM Pairs
getPairs b = pairs . maybe "" BS.concat <$> runPipe (b =$= toList)

login :: PeyotlsHandle -> Acc.Connection -> Maybe User -> Pairs -> St -> PeyotlsM ()
login t _ _ np (ut, g) = do
	let Just (n, p) =
		(,) <$> lookup "user_name" np <*> lookup "user_password" np
	mu <- io $ bool (return Nothing) (Just <$> addUser ut (uuid4IO g) n)
		=<< Acc.chkLogin (Acc.UserName n) (Acc.Password p)
	liftIO $ print mu
	flip (maybe $ showFile t html "static/index.html") mu $ \u -> do
		m <- io $ setUName (User n) =<< BS.readFile "static/i_know.html"
		setCookiePage t [m] $ cookie u

logout :: Page
logout = Dynamic $ \t _ _ _ _ -> do
	m <- io $ BS.readFile "static/index.html"
	setCookiePage t [m] logoutCookie

activate :: Page
activate = Dynamic $ \t _ _ up _ -> do
	let Just ak = lookup "activation_key" up
	liftIO $ Acc.activate (read $ unp ak)
	showFile t html "static/activated.html"

doActivate :: Maybe FilePath -> IO ()
doActivate (Just fp) = do
	ac <- readFile ("passwords/" ++ fp)
	print ac
	case words ac of
		[s, h, _] -> writeFile ("passwords/" ++ fp) . (++ "\n") $
			unwords [s, h]
		_ -> return ()
doActivate _ = return ()

signup :: Page
signup = Dynamic $ \t conn _ up (_ut, _rg) -> do
		let	Just un = lookup "user_name" up
			Just ma = lookup "mail_address" up
			Just p = lookup "user_password" up
			Just rp = lookup "re_user_password" up
			Just cp = lookup "captcha" up
		liftIO $ print ma
		liftIO . print $ p == rp
		liftIO $ BSC.putStrLn cp
		liftIO $ getZonedTime >>= print
		liftIO $ BSC.putStrLn un
		liftIO $ BSC.putStrLn p
		if cp /= "%E3%83%8F%E3%83%9F%E3%83%B3%E3%82%B0%E3%83%90%E3%83%BC%E3%83%89" || p /= rp
		then showFile t html "static/badcaptcha.html"
		else do	-- _ <- liftIO $ mkAccount un p
			ret <- liftIO $ Acc.newAccount conn
				(Acc.UserName un) (Acc.MailAddress ma)
				(Acc.Password p)
			case ret of
				Left _ -> showFile t html "static/user_exist.html"
				Right uuid -> do
					showFile t html "static/signup_done.html"
					liftIO $ do
						print uuid
						mailTo ma uuid

addUser :: UTable -> IO UUID4 -> BS.ByteString -> IO UUID4
addUser ut gt nm = do
	ssn <- readIORef ut
	u <- gt
	writeIORef ut $ (u, nm) : ssn
	return u

getUser :: UTable -> Maybe UUID4 -> IO (Maybe BS.ByteString)
getUser ut (Just u) = lookup u <$> readIORef ut
getUser _ _ = return Nothing

getUUID4 :: [(BS.ByteString, BS.ByteString)] -> Maybe UUID4
getUUID4 c = read . unp . snd <$> listToMaybe c

cookie :: UUID4 -> SetCookie
cookie u = SetCookie {
	cookieName = "uuid",
	cookieValue = BSC.pack $ show u,
	cookieExpires = Nothing,
	cookieMaxAge = Just 3600,
	cookieDomain = Just "skami2.iocikun.jp",
	cookiePath = Just "/",
	cookieSecure = True,
	cookieHttpOnly = True,
	cookieExtension = []
	}

logoutCookie :: SetCookie
logoutCookie = SetCookie {
	cookieName = "uuid",
	cookieValue = "",
	cookieExpires = Nothing,
	cookieMaxAge = Just 0,
	cookieDomain = Just "skami2.iocikun.jp",
	cookiePath = Just "/",
	cookieSecure = True,
	cookieHttpOnly = True,
	cookieExtension = []
	}

setUName :: User -> BS.ByteString -> IO BS.ByteString
setUName u@(User un) t = do
	ma <- Acc.mailAddress (Acc.UserName un)
	ih <- Acc.isHbmember (Acc.UserName un)
	fromJust <$> template (homeLookup u ma ih) homeValues t

homeLookup ::
	User -> Maybe Acc.MailAddress -> Bool -> BS.ByteString -> [BS.ByteString]
homeLookup (User un) _ _ "user_name" = [un]
homeLookup _ (Just (Acc.MailAddress ma)) _ "mail_address" = [decode ma]
homeLookup _ _ _ "mail_address" = ["no address"]
homeLookup _ _ _ "line" = ["hello", "world"]
homeLookup _ _ False "is_hbmember" = [""]
homeLookup _ _ _ "is_hbmember" = ["You are HB member"]
homeLookup _ _ _ _ = []

homeValues :: BS.ByteString -> IO [BS.ByteString]
homeValues "LINE" = (<$> Acc.getRequests) . map $ \(x, y, z) ->
	BSC.unwords [
		BS.concat ["<a href=\"/requests/", x, "\">", x, "</a>"],
		y,
		decode z ]
homeValues _ = return []

showFile :: PeyotlsHandle -> ContentType -> FilePath -> PeyotlsM ()
showFile t ct fp = showPage t ct =<< liftIO (BS.readFile fp)

showPage :: PeyotlsHandle -> ContentType -> BS.ByteString -> PeyotlsM ()
showPage t ct as = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	$ LBS.fromChunks [as]) { responseContentType = ct, responseOthers = hsts }

setCookiePage :: PeyotlsHandle -> [BS.ByteString] -> SetCookie -> PeyotlsM ()
setCookiePage t as u = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	$ LBS.fromChunks as) {
		responseContentType = ContentType Text Html [],
		responseSetCookie = [u],
		responseOthers = hsts }

pairs :: BS.ByteString -> Pairs
pairs s = (`map` filter (BSC.any $ not . isSpace) (BSC.split '&' s)) $ \ss ->
	case BSC.split '=' ss of
		[n, v] -> (n, v)
		_ -> error $ "pairs: bad " ++ show ss

unp :: BS.ByteString -> String
unp = BSC.unpack

pck :: String -> BS.ByteString
pck = BSC.pack

io :: MonadIO m => IO a -> m a
io = liftIO

hsts :: [(BSC.ByteString, BSC.ByteString)]
hsts = [
	("Strict-Transport-Security",
		"max-age=31536000; includeSubDomains; preload")
	]
