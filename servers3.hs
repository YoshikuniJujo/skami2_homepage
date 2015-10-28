{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative ((<$>), (<*>))
import "monads-tf" Control.Monad.State (
	MonadIO, liftIO, forever, void, StateT(..), runStateT )
import Control.Concurrent (forkIO)
import Data.Bool (bool)
import Data.Maybe (listToMaybe)
import Data.List (isPrefixOf)
import Data.HandleLike (hlClose)
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

type Req = Request PeyotlsHandle
type RndGen = IORef SystemRNG
type UTable = IORef [(UUID4, String)]

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

resp :: Request PeyotlsHandle -> IORef [(UUID4, String)] -> PeyotlsHandle ->
	IORef SystemRNG -> PeyotlsM ()
resp r ut t rg = case r of
	RequestGet (Path "/") _v g -> index t g ut
	RequestGet (Path "/signup") _v _g -> showFile t "static/signup.html"
	RequestGet (Path "/activate") _v _g -> showFile t "static/to_activate.html"
	RequestPost (Path "/login") _v _pst -> login t r ut rg
	RequestPost (Path "/signup") _v pst -> signup pst r ut t rg
	RequestPost (Path "/activate") _v _pst -> activatePost r t
	RequestGet (Path p) _ _ -> case span (/= '?') $ BSC.unpack p of
		("/activate", '?' : ak) -> activate t ak
		_ -> error $ "bad: path = " ++ BSC.unpack p
	_ -> error "bad"
	
index :: PeyotlsHandle -> Get -> IORef [(UUID4, String)] -> PeyotlsM ()
index t g ut = (io (getUser ut $ getUUID4 g) >>=)
	. maybe (showFile t "static/index.html")
	$ (=<< io (readFile "static/i_know.html")) . (showPage t .) . setUName

login :: PeyotlsHandle -> Req -> UTable -> RndGen -> PeyotlsM ()
login t r ut g = do
	np <- pairs . maybe "" (>>= unp) <$> runPipe (requestBody r =$= toList)
	let Just (n, p) =
		(,) <$> lookup "user_name" np <*> lookup "user_password" np
	mu <- io $ bool (return Nothing) (Just <$> addUser ut (uuid4IO g) n)
		=<< checkHash (pck n) (pck p)
	flip (maybe $ showFile t "static/index.html") mu $ \u -> do
		m <- io $ setUName n <$> readFile "static/login.html"
		setCookiePage t [m] u

activatePost :: Request PeyotlsHandle -> PeyotlsHandle -> PeyotlsM ()
activatePost r t = activate t
	. maybe "" (concatMap BSC.unpack) =<< runPipe (requestBody r =$= toList)

activate :: PeyotlsHandle -> String -> PeyotlsM ()
activate t up_ = do
	let	up = map ((\(n : v : _) -> (n, v)) . split '=') $ split '&' up_
		Just ak = lookup "activation_key" up
	liftIO $ getActi ak >>= doActivate
	showFile t "static/activated.html"

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

signup :: Post a -> Request PeyotlsHandle -> IORef [(UUID4, String)] -> PeyotlsHandle ->
	IORef SystemRNG -> PeyotlsM ()
signup pst r _ut t rg = do
		liftIO $ do
			putStrLn "POST"
			print $ postCookie pst
		up_ <- runPipe $
			requestBody r =$= toList
		let	up = map ((\[n, v] -> (n, v)) . split '=')
				. split '&'
				$ maybe "" (concatMap BSC.unpack) up_
			Just un = lookup "user_name" up
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
		then showFile t "static/badcaptcha.html"
		else do	b <- liftIO $ mkAccount (BSC.pack un) (BSC.pack p)
			showFile t $ if not b
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

addUser :: IORef [(UUID4, String)] -> IO UUID4 -> String -> IO UUID4
addUser ut gt nm = do
	ssn <- readIORef ut
	u <- gt
	writeIORef ut $ (u, nm) : ssn
	return u

getUser :: IORef [(UUID4, String)] -> Maybe UUID4 -> IO (Maybe String)
getUser ut (Just u) = lookup u <$> readIORef ut
getUser _ _ = return Nothing

getUUID4 :: Get -> Maybe UUID4
getUUID4 g = read . BSC.unpack . snd <$> listToMaybe (getCookie g)

cookie :: UUID4 -> SetCookie
cookie u = SetCookie {
	cookieName = "uuid",
	cookieValue = BSC.pack $ show u,
	cookieExpires = Nothing,
	cookieMaxAge = Just 10,
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

showFile :: PeyotlsHandle -> FilePath -> PeyotlsM ()
showFile t fp = showPage t =<< liftIO (readFile fp)

showPage :: PeyotlsHandle -> String -> PeyotlsM ()
showPage t as = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	. LBS.fromChunks $ map BSU.fromString [as]) {
		responseContentType = ContentType Text Html [] }

setCookiePage :: PeyotlsHandle -> [String] -> UUID4 -> PeyotlsM ()
setCookiePage t as u = putResponse t
	((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
	. LBS.fromChunks $ map BSU.fromString as) {
		responseContentType = ContentType Text Html [],
		responseSetCookie = [cookie u] }

pairs :: String -> [(String, String)]
pairs = map ((\[n, v] -> (n, v)) . split '=') . split '&'

unp :: BS.ByteString -> String
unp = BSC.unpack

pck :: String -> BS.ByteString
pck = BSC.pack

io :: MonadIO m => IO a -> m a
io = liftIO
