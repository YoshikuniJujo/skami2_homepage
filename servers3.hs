{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative ((<$>), (<*>))
import Control.Arrow ((***))
import "monads-tf" Control.Monad.State (
	MonadIO, liftIO, forever, void, StateT(..), runStateT )
import Control.Concurrent (forkIO)
import Data.Bool (bool)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.List (isPrefixOf)
import Data.Char (isSpace)
import Data.HandleLike (hlClose, HandleMonad)
import Data.Pipe (Pipe, runPipe, await, (=$=))
import Data.Pipe.List (toList)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Time (getZonedTime)
import System.IO (Handle)
import Numeric (showHex)
import Network (PortID(..), listenOn, accept)
import Network.PeyoTLS.Server (
	CipherSuite, PeyotlsM, PeyotlsHandle, TlsHandle, run, open)
import Network.PeyoTLS.ReadFile (readKey, readCertificateChain)
import Network.TigHTTP.Server (getRequest, putResponse, response, requestBody)
import Network.TigHTTP.Types (
	Request(..), Path(..), Get(..), Post(..),
	Response(..), ContentType(..), Type(..), Subtype(..), SetCookie(..) )
import "crypto-random" Crypto.Random (
	SystemRNG, createEntropyPool, cprgCreate, cprgFork )

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.UTF8 as BSU

import UUID4 (UUID4, newGen, uuid4IO)
import MakeHash
import MailTo

type Body = Pipe () BS.ByteString (HandleMonad PeyotlsHandle) ()
type Pairs = [(String, String)]
type Cookie = [(String, String)]
type RndGen = IORef SystemRNG
type UTable = IORef [(UUID4, String)]
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
		<$> readKey "2014_private_de.key"
		<*> readCertificateChain ["2014_cert.pem"]
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
	(pt, '?' : pr) -> (Path $ pck pt, Just $ pairs pr)
	_ -> (p, Nothing)
path (RequestPost p _ _) = (p, Nothing)
path (RequestRaw _ p _ _) = (p, Nothing)

resp :: Request PeyotlsHandle -> UTable -> PeyotlsHandle -> RndGen -> PeyotlsM ()
resp r ut t rg = do
	pr_ <- getPairs $ requestBody r
	let	(pt, mpr) = path r
		pr = fromMaybe pr_ mpr
		c = map (unp *** unp) $ case r of
			RequestGet _ _ g -> getCookie g
			RequestPost _ _ pst -> postCookie pst
			_ -> []
		s = (ut, rg)
		mh = lookup (not $ null pr, pt) pages
	liftIO $ print pr
	liftIO $ print c
	case mh of
		Just (Static ct pg) -> showFile t ct pg
		Just (Dynamic f) -> f t c pr s
		_ -> error $ "badbadbad:" ++ show pt

pages :: [((Bool, Path), Page)]
pages = [
	((False, Path "/"), index),
	((False, Path "/login"), index),
	((True, Path "/login"), login),
	((False, Path "/logout"), logout),
	((False, Path "/signup"), Static html "static/signup.html"),
	((True, Path "/signup"), signup),
	((False, Path "/activate"), Static html "static/to_activate.html"),
	((True, Path "/activate"), activate),
	((False, Path "/robots.txt"), Static text "static/robots.txt")]

html, text :: ContentType
html = ContentType Text Html []
text = ContentType Text Plain []

data Page
	= Static { contentType :: ContentType, static :: FilePath }
	| Dynamic {
		dynamic :: PeyotlsHandle -> Cookie -> Pairs -> St -> PeyotlsM ()
		}
	
index :: Page
index = Dynamic $ \t c _ (ut, _) -> (io (getUser ut $ getUUID4 c) >>=)
	. maybe (showFile t html "static/index.html")
	$ (=<< io (readFile "static/i_know.html")) . (showPage t html .) . setUName

getPairs :: Body -> PeyotlsM Pairs
getPairs b = pairs . maybe "" (>>= unp) <$> runPipe (b =$= toList)

login :: Page
login = Dynamic $ \t _ np (ut, g) -> do
	let Just (n, p) =
		(,) <$> lookup "user_name" np <*> lookup "user_password" np
	mu <- io $ bool (return Nothing) (Just <$> addUser ut (uuid4IO g) n)
		=<< checkHash (pck n) (pck p)
	flip (maybe $ showFile t html "static/index.html") mu $ \u -> do
		m <- io $ setUName n <$> readFile "static/login.html"
		setCookiePage t [m] $ cookie u

logout :: Page
logout = Dynamic $ \t _ _ _ -> do
	m <- io $ readFile "static/index.html"
	setCookiePage t [m] logoutCookie

activate :: Page
activate = Dynamic $ \t _ up _ -> do
	let Just ak = lookup "activation_key" up
	liftIO $ getActi ak >>= doActivate
	showFile t html "static/activated.html"

getActi :: String -> IO (Maybe String)
getActi s = do
	c <- readFile "actidict.txt"
	let d = map ((\[k, v] -> (k, v)) . words) $ lines c
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
signup = Dynamic $ \t _ up (_ut, rg) -> do
		let	Just un = lookup "user_name" up
			Just ma = lookup "mail_address" up
			Just p = lookup "user_password" up
			Just rp = lookup "re_user_password" up
			Just cp = lookup "captcha" up
		liftIO $ print ma
		liftIO . print $ p == rp
		liftIO $ putStrLn cp
		liftIO $ getZonedTime >>= print
		liftIO $ putStrLn un
		liftIO $ putStrLn p
		if cp /= "%E3%83%8F%E3%83%9F%E3%83%B3%E3%82%B0%E3%83%90%E3%83%BC%E3%83%89" || p /= rp
		then showFile t html "static/badcaptcha.html"
		else do	b <- liftIO $ mkAccount (BSC.pack un) (BSC.pack p)
			showFile t html $ if not b
				then "static/user_exist.html"
				else "static/signup_done.html"
			liftIO $ do
				uuid <- uuid4IO rg
				print uuid
				addActivate un uuid
				mailTo ma uuid

addActivate :: String -> UUID4 -> IO ()
addActivate ac ui = do
	c <- readFile "actidict.txt"
	print c
	writeFile "actidict.txt" $ c ++ show ui ++ " " ++ ac ++ "\n"

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

showH :: (Show a, Integral a) => a -> String
showH n = replicate (2 - length s) '0' ++ s
	where s = showHex n ""

addUser :: UTable -> IO UUID4 -> String -> IO UUID4
addUser ut gt nm = do
	ssn <- readIORef ut
	u <- gt
	writeIORef ut $ (u, nm) : ssn
	return u

getUser :: UTable -> Maybe UUID4 -> IO (Maybe String)
getUser ut (Just u) = lookup u <$> readIORef ut
getUser _ _ = return Nothing

getUUID4 :: [(String, String)] -> Maybe UUID4
getUUID4 c = read . snd <$> listToMaybe c

cookie :: UUID4 -> SetCookie
cookie u = SetCookie {
	cookieName = "uuid",
	cookieValue = BSC.pack $ show u,
	cookieExpires = Nothing,
	cookieMaxAge = Just 60,
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

setUName :: String -> String -> String
setUName un ('$' : cs)
	| "user_name" `isPrefixOf` cs = un ++ setUName un (drop 9 cs)
setUName un (c : cs) = c : setUName un cs
setUName _ _ = ""

showFile :: PeyotlsHandle -> ContentType -> FilePath -> PeyotlsM ()
showFile t ct fp = showPage t ct =<< liftIO (readFile fp)

showPage :: PeyotlsHandle -> ContentType -> String -> PeyotlsM ()
showPage t ct as = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	. LBS.fromChunks $ map BSU.fromString [as]) { responseContentType = ct }

setCookiePage :: PeyotlsHandle -> [String] -> SetCookie -> PeyotlsM ()
setCookiePage t as u = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	. LBS.fromChunks $ map BSU.fromString as) {
		responseContentType = ContentType Text Html [],
		responseSetCookie = [u] }

pairs :: String -> Pairs
pairs s = (`map` filter (any $ not . isSpace) (split '&' s)) $ \ss ->
	case split '=' ss of
		[n, v] -> (n, v)
		_ -> error $ "pairs: bad " ++ show ss

unp :: BS.ByteString -> String
unp = BSC.unpack

pck :: String -> BS.ByteString
pck = BSC.pack

io :: MonadIO m => IO a -> m a
io = liftIO
