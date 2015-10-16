{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import "monads-tf" Control.Monad.State
import Control.Concurrent
import Data.Maybe
import Data.List
import Data.HandleLike
import Data.Pipe
import Data.Pipe.List
import Data.Time
import System.IO
import Numeric
import Network
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import Network.TigHTTP.Server
import Network.TigHTTP.Types
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.UTF8 as BSU
import qualified Crypto.Hash.SHA256 as SHA256

import Data.IORef
import UUID4

main :: IO ()
main = do
	rg <- newIORef =<< newGen
	let uuid4 = do
		g <- readIORef rg
		let (u, g') = mkUUID4 g
		writeIORef rg g'
		return u
	rssn <- newIORef []
	k <- readKey "2014_private_de.key"
	c <- readCertificateChain ["2014_cert.pem"]
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	soc <- listenOn $ PortNumber 443
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		void . liftIO . forkIO . (`run` g) $ do
			t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)]
				Nothing
			r <- getRequest t
			resp r rssn t uuid4
			hlClose t

resp :: Request PeyotlsHandle -> IORef [(UUID4, String)] -> PeyotlsHandle ->
	IO UUID4 -> PeyotlsM ()
resp r rssn t uuid4 =
			case r of
				RequestGet _p _v g -> do
					mun <- liftIO $ getUser rssn (read . BSC.unpack . snd <$> listToMaybe (getCookie g))
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
							$ maybe "" (concat . map BSC.unpack) up_
						Just un = lookup "user_name" up
						Just p = lookup "user_password" up
					liftIO $ getZonedTime >>= print
					liftIO $ putStrLn un
					liftIO $ putStrLn p
					tbl <- liftIO $ passwordTable
					let slt = maybe "" id $ getSalt (BSC.pack un) tbl
					let pw = maybe "" BSC.unpack $ getPw (BSC.pack un) tbl
					let hs = iterate SHA256.hash 
						(BSC.pack p `BS.append` slt) !! 10000
					let pw' = concatMap showH $ BS.unpack hs
					liftIO $ print pw
					liftIO $ print pw'
					liftIO . print $ pw == pw'
					u <- if pw == pw'
						then Just <$>
							liftIO (addUser rssn uuid4 un)
						else return Nothing
					pg <- liftIO $ readFile "static/login.html"
					let msg = flip setUserName pg (if pw == pw' then un else "Nobody")
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
passwordTable = map (\[u, s, p] -> (u, s, p))
	. map (map BSC.pack . words) . lines <$> readFile "password.txt"

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
