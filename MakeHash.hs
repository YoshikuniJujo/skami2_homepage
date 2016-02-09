{-# LANGUAGE OverloadedStrings #-}

module MakeHash (mkAccount) where

import Control.Applicative
import System.Directory
import Numeric

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import System.Random

mkAccount :: BSC.ByteString -> BSC.ByteString -> IO Bool
mkAccount u p = do
	b <- doesFileExist $ "passwords/" ++ BSC.unpack u
	if b then return False else do
--		let s = "01234567890123456789"
		s <- BSC.pack . show <$> (randomIO :: IO Int)
		writeFile ("passwords/" ++ BSC.unpack u)
			. (++ " False") . ((BSC.unpack s ++ " ") ++)
			. concatMap showH . BS.unpack $ mkHash p s
		return True

mkHash :: BSC.ByteString -> BSC.ByteString -> BSC.ByteString
mkHash p s = iterate SHA256.hash (p `BSC.append` s) !! 10000

showH :: (Show a, Integral a) => a -> String
showH n = replicate (2 - length s) '0' ++ s
	where
	s = showHex n ""
