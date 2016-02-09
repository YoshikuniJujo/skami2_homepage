{-# LANGUAGE OverloadedStrings #-}

module Account.Hash (
	Password(..), Salt(..), Hash(..), createHash, chkHash, mkHash
	) where

import Control.Applicative
import Control.Arrow
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.Random
import qualified Crypto.Hash.SHA256 as SHA256

newtype Password = Password BS.ByteString deriving Show
newtype Salt = Salt BS.ByteString deriving Show
newtype Hash = Hash BS.ByteString deriving (Show, Eq)

createHash :: Password -> IO (Salt, Hash)
createHash p = (id &&& mkHash p) <$> getSalt

chkHash :: Password -> Salt -> Hash -> Bool
chkHash p s h = mkHash p s == h

mkHash :: Password -> Salt -> Hash
mkHash (Password p) (Salt s) =
	Hash $ iterate SHA256.hash (p `BS.append` s) !! 10000

getSalt :: IO Salt
getSalt = Salt . BSC.pack . show <$> (randomIO :: IO Word64)
