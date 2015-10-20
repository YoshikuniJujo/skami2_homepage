{-# LANGUAGE OverloadedStrings #-}

module MakeHash (mkAccount, checkHash) where

import Control.Applicative
import System.Environment
import System.Directory
import Numeric

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import System.Random

main :: IO ()
main = do
	u_ : p_ : s_ : _ <- getArgs
	let	u = BSC.pack u_
		p = BSC.pack p_
		s = BSC.pack s_
	BSC.putStr s
	putChar ' '
	putStrLn . concatMap showH . BS.unpack $ mkHash p s
	mkAccount u p
	checkHash u p >>= print
--	getHash u >>= putStrLn . concatMap showH . BS.unpack
--	putStrLn . concatMap showH . BS.unpack $ iterate SHA256.hash pl !! 10000

checkHash :: BSC.ByteString -> BSC.ByteString -> IO Bool
checkHash u p = do
	b <- doesFileExist $ "passwords/" ++ BSC.unpack u
	if b
	then do	(s, h) <- getHash u
		return $ BSC.pack (concatMap showH (BS.unpack $ mkHash p s)) == h
	else return False

getHash :: BSC.ByteString -> IO (BSC.ByteString, BSC.ByteString)
getHash u = do
	[s, h] <- words <$> readFile ("passwords/" ++ BSC.unpack u)
	return (BSC.pack s, BSC.pack h)

mkAccount :: BSC.ByteString -> BSC.ByteString -> IO Bool
mkAccount u p = do
	b <- doesFileExist $ "passwords/" ++ BSC.unpack u
	if b then return False else do
--		let s = "01234567890123456789"
		s <- BSC.pack . show <$> (randomIO :: IO Int)
		writeFile ("passwords/" ++ BSC.unpack u)
			. ((BSC.unpack s ++ " ") ++)
			. concatMap showH . BS.unpack $ mkHash p s
		return True

mkHash :: BSC.ByteString -> BSC.ByteString -> BSC.ByteString
mkHash p s = iterate SHA256.hash (p `BSC.append` s) !! 10000

showH :: (Show a, Integral a) => a -> String
showH n = replicate (2 - length s) '0' ++ s
	where
	s = showHex n ""
