{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative ((<$>), (<*>))
import "monads-tf" Control.Monad.State (
	MonadIO, liftIO, forever, void, StateT(..), runStateT )
import Control.Concurrent (forkIO)
import Data.Maybe (fromMaybe, maybeToList, listToMaybe)
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
	Request(..), Get(..), Post(..),
	Response(..), ContentType(..), Type(..), Subtype(..), SetCookie(..) )
import "crypto-random" Crypto.Random (
	SystemRNG, createEntropyPool, cprgCreate, cprgFork )

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.UTF8 as BSU
import qualified Crypto.Hash.SHA256 as SHA256

import UUID4 (UUID4, newGen, mkUUID4)

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
	(k, c, g0, rssn, rg) <- (,,,,)
		<$> readKey "2014_private_de.key"
		<*> readCertificateChain ["2014_cert.pem"]
		<*> (cprgCreate <$> createEntropyPool :: IO SystemRNG)
		<*> newIORef []
		<*> (newIORef =<< newGen)
	soc <- listenOn $ PortNumber 443
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		void . liftIO . forkIO . (`run` g) $ do
			t <- open h cipherSuites [(k, c)] Nothing
			r <- getRequest t
			resp r rssn t rg
			hlClose t

uuid4IO :: IORef SystemRNG -> IO UUID4
uuid4IO rg = do
	g <- readIORef rg
	let (u, g') = mkUUID4 g
	writeIORef rg g'
	return u

resp :: Request PeyotlsHandle -> IORef [(UUID4, String)] -> PeyotlsHandle ->
	IORef SystemRNG -> PeyotlsM ()
resp r rssn t rg = case r of
	RequestGet _p _v g -> do
		mun <- liftIO . getUser rssn $ getUUID4 g
		case mun of
			Just un -> do
				as <- liftIO $ (: []) . setUserName un <$> readFile "static/i_know.html"
				putResponse t
					((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
					. LBS.fromChunks $ map BSU.fromString as) {
						responseContentType = ContentType Text Html []
						}
			_ -> do
				as <- liftIO $ (: []) <$> readFile "static/index.html"
				putResponse t
					((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
					. LBS.fromChunks $ map BSU.fromString as) {
						responseContentType = ContentType Text Html []
						}
	RequestPost _p _v pst -> do
		liftIO $ do
			putStrLn "POST"
			print $ postCookie pst
		up_ <- runPipe $
			requestBody r =$= toList
		let	up = map ((\[n, v] -> (n, v)) . split '=')
				. split '&'
				$ maybe "" (concatMap BSC.unpack) up_
			Just un = lookup "user_name" up
			Just p = lookup "user_password" up
		liftIO $ getZonedTime >>= print
		liftIO $ putStrLn un
		liftIO $ putStrLn p
		tbl <- liftIO passwordTable
		let slt = fromMaybe "" $ getSalt (BSC.pack un) tbl
		let pw = maybe "" BSC.unpack $ getPw (BSC.pack un) tbl
		let hs = iterate SHA256.hash 
			(BSC.pack p `BS.append` slt) !! 10000
		let pw' = concatMap showH $ BS.unpack hs
		liftIO $ print pw
		liftIO $ print pw'
		liftIO . print $ pw == pw'
		u <- if pw == pw'
			then Just <$>
				liftIO (addUser rssn (uuid4IO rg) un)
			else return Nothing
		pg <- liftIO $ readFile "static/login.html"
		let msg = flip setUserName pg $ if pw == pw' then un else "Nobody"
		putResponse t
			((response :: LBS.ByteString -> Response Pipe (TlsHandle Handle SystemRNG))
			. LBS.fromChunks $ map BSU.fromString [msg]) {
				responseContentType = ContentType Text Html [],
				responseSetCookie = maybeToList $ cookie <$> u
				}
	_ -> error "bad"

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
addUser rssn gt nm = do
	ssn <- readIORef rssn
	u <- gt
	writeIORef rssn $ (u, nm) : ssn
	return u

getUser :: IORef [(UUID4, String)] -> Maybe UUID4 -> IO (Maybe String)
getUser rssn (Just u) = lookup u <$> readIORef rssn
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

setUserName :: String -> String -> String
setUserName un ('$' : cs)
	| "user_name" `isPrefixOf` cs = un ++ setUserName un (drop 9 cs)
setUserName un (c : cs) = c : setUserName un cs
setUserName _ _ = ""
