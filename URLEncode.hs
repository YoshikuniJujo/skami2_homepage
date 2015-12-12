{-# LANGUAGE OverloadedStrings #-}

module URLEncode (decode) where

import Data.Maybe
import Data.List
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

decode :: BS.ByteString -> BS.ByteString
decode s = case BSC.uncons s of
	Just ('%', cs) -> let (h, cs') = BS.splitAt 2 cs in hex h `BS.cons` decode cs'
	Just ('+', cs) -> ' ' `BSC.cons` decode cs
	Just (c, cs) -> c `BSC.cons` decode cs
	_ -> ""

hex :: BS.ByteString -> Word8
hex = hx . BS.reverse
	where
	hx s = case BSC.uncons s of
		Just (c, cs) -> fromIntegral (fromJust $ c `elemIndex` digits) +
			16 * hx cs
		_ -> 0

digits :: String
digits = "0123456789ABCDEF"
