module UUID4 (UUID4, newGen, uuid4IO) where

import Control.Applicative
import Control.Arrow
import Data.List
import Data.Bits
import Data.Word
import qualified Data.ByteString as BS
import Data.IORef
import Crypto.Random
import Numeric

data UUID4 = UUID4 BS.ByteString deriving Eq

instance Show UUID4 where
	show (UUID4 u) = intercalate "-"
		. map (concatMap showH)
		. (`splitIn` [4, 2, 2, 2, 6]) $ BS.unpack u

instance Read UUID4 where
	readsPrec _ s = [(
		UUID4 . BS.pack . map readH . (`splitN` 2) $ filter (/= '-') s,
		"")]

uuid4IO :: IORef SystemRNG -> IO UUID4
uuid4IO rg = do
	g <- readIORef rg
	let (u, g') = mkUUID4 g
	writeIORef rg g'
	return u

readH :: String -> Word8
readH = fst . head . readHex

setB :: [Word8] -> Int -> [Word8]
setB ws n = pr ++ b `setBit` i : ps
	where
	(a, i) = (7 -) `second` (n `divMod` 8)
	(pr, b : ps) = splitAt a ws

clearB :: [Word8] -> Int -> [Word8]
clearB ws n = pr ++ b `clearBit` i : ps
	where
	(a, i) = (7 -) `second` (n `divMod` 8)
	(pr, b : ps) = splitAt a ws

splitIn :: [a] -> [Int] -> [[a]]
splitIn _ [] = []
splitIn [] _ = []
splitIn xs (i : is) = take i xs : splitIn (drop i xs) is

splitN :: [a] -> Int -> [[a]]
splitN [] _ = []
splitN xs i = take i xs : splitN (drop i xs) i

newGen :: IO SystemRNG
newGen = cprgCreate <$> createEntropyPool

mkUUID4 :: SystemRNG -> (UUID4, SystemRNG)
mkUUID4 = first (
		UUID4 . BS.pack
			. (`clearB` 48) . (`setB` 49)
			. (`clearB` 50) . (`clearB` 51)
			. (`setB` 64) . (`clearB` 65)
			. BS.unpack )
	. cprgGenerate 16

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where s = showHex w ""
