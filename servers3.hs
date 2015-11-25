{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative ((<$>), (<*>))
import "monads-tf" Control.Monad.State (
	MonadIO, liftIO, forever, void, StateT(..), runStateT )
import Control.Concurrent (forkIO)
import Data.Bool (bool)
import Data.Maybe (fromMaybe, fromJust, maybeToList, listToMaybe)
import Data.Char (isSpace)
import Data.HandleLike (hlClose, HandleMonad)
import Data.Pipe (Pipe, runPipe, (=$=))
import Data.Pipe.List (toList)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Time (getZonedTime)
import System.IO (Handle)
import Network (PortID(..), listenOn, accept)
import Network.PeyoTLS.Server (
	CipherSuite, PeyotlsM, PeyotlsHandle, TlsHandle, run, open)
import Network.PeyoTLS.ReadFile (readKey, readCertificateChain)
import Network.TigHTTP.Server (getRequest, putResponse, response, requestBody)
import Network.TigHTTP.Types (
	Request(..), Path(..), Get(..), Post(..),
	Response(..), ContentType(..), Type(..), Subtype(..), SetCookie(..),
	StatusCode(..) )
import "crypto-random" Crypto.Random (
	SystemRNG, createEntropyPool, cprgCreate, cprgFork )
import Text.Template (template)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS
-- import qualified Data.Text as T

import UUID4 (UUID4, newGen, uuid4IO)
import MakeHash
import MailTo

import qualified Account as Acc

type Body = Pipe () BS.ByteString (HandleMonad PeyotlsHandle) ()
type Pairs = [(BS.ByteString, BS.ByteString)]
-- type Cookie = [(BS.ByteString, BS.ByteString)]
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

resp :: Request PeyotlsHandle -> UTable -> PeyotlsHandle -> RndGen -> PeyotlsM ()
resp r ut t rg = do
	pr_ <- getPairs $ requestBody r
	let	(pt, mpr) = path r
		pr = fromMaybe pr_ mpr
		c = case r of
			RequestGet _ _ g -> getCookie g
			RequestPost _ _ pst -> postCookie pst
			_ -> []
		s = (ut, rg)
		mh = lookup (not $ null pr, pt) pages
	liftIO $ print pr
	liftIO $ print c
	mu <- (User <$>) <$> io (getUser ut $ getUUID4 c)
	conn <- liftIO Acc.open
	case mh of
		Just (Static ct pg) -> showFile t ct pg
		Just (Dynamic f) -> f t conn mu pr s
		_ -> do	io . putStrLn $ "badbadbad:" ++ show pt
			putResponse t (response' $ LBS.fromChunks ["404 File not found"]) {
				responseStatusCode = NotFound,
				responseContentType = text,
				responseOthers = hsts }

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

html, text, ico :: ContentType
html = ContentType Text Html []
text = ContentType Text Plain []
ico = ContentType (TypeRaw "image") (SubtypeRaw "vnd.microsoft.icon") []

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
--		=<< checkHash n p
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
	liftIO $ getActi ak >>= doActivate . (unp <$>)
	liftIO $ Acc.activate (read $ unp ak)
	showFile t html "static/activated.html"

getActi :: BS.ByteString -> IO (Maybe BS.ByteString)
getActi s = do
	c <- BS.readFile "actidict.txt"
	let d = map ((\[k, v] -> (k, v)) . BSC.words) $ BSC.lines c
	return $ lookup s d

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
		else do	_ <- liftIO $ mkAccount un p
			ret <- liftIO $ Acc.newAccount conn
				(Acc.UserName un) (Acc.MailAddress ma)
				(Acc.Password p)
			case ret of
				Left _ -> showFile t html "static/user_exist.html"
				Right uuid -> do
					showFile t html "static/signup_done.html"
					liftIO $ do
					--	uuid <- uuid4IO rg
						print uuid
						addActivate un uuid
						mailTo ma uuid

addActivate :: BS.ByteString -> UUID4 -> IO ()
addActivate ac ui = do
	c <- readFile "actidict.txt"
	print c
	writeFile "actidict.txt" $ c ++ show ui ++ " " ++ unp ac ++ "\n"

{-
printP :: MonadIO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ()) (\s -> liftIO (BSC.putStr s) >> printP)

passwordTable :: IO [(BS.ByteString, BS.ByteString, BS.ByteString)]
passwordTable = map
		((\[u, s, p] -> (u, s, p)) . map BSC.pack . words)
	. lines <$> readFile "password.txt"

getSalt, getPw :: BS.ByteString ->
	[(BS.ByteString, BS.ByteString, BS.ByteString)] -> Maybe BS.ByteString
getSalt _ [] = Nothing
getSalt u0 ((u, s, _) : uss)
	| u == u0 = Just s
	| otherwise = getSalt u0 uss

getPw _ [] = Nothing
getPw u0 ((u, _, p) : uss)
	| u == u0 = Just p
	| otherwise = getPw u0 uss

split :: Eq a => a -> [a] -> [[a]]
split _ [] = [[]]
split s (x : xs)
	| x == s = [] : split s xs
	| otherwise = (x :) `heading` split s xs
	where heading f (y : ys) = f y : ys; heading _ _ = error "bad"
	-}

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
setUName (User un) t = do
	ma <- Acc.mailAddress (Acc.UserName un)
	fromJust <$> template
		(\s -> maybeToList $ lookup s [
			("user_name", un),
			("mail_address", maybe "no address"
				(\(Acc.MailAddress a) -> a) ma)])
--		(\s -> case s of "user_name" -> [un]; _ -> [""])
		(const $ return [""]) t

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
