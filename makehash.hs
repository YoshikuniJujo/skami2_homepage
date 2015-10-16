{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.Environment
import Numeric

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

main :: IO ()
main = do
	u : p : s : _ <- getArgs
	let pl = BSC.pack $ p ++ s
	putStr u
	putChar ' '
	putStrLn . concatMap showH . BS.unpack $ iterate SHA256.hash pl !! 10000

showH :: (Show a, Integral a) => a -> String
showH n = replicate (2 - length s) '0' ++ s
	where
	s = showHex n ""
