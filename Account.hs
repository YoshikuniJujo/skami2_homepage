{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Account (
	Connection,
	UserName(..), MailAddress(..), Password(..), MkAccErr(..),
	open, newAccount, activate, chkLogin, mailAddress, isHbmember,

	insertRequest, getRequests, getReqDescription,

	insertImage, getImages,
	) where

import Control.Applicative
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64
import Data.IORef
import "crypto-random" Crypto.Random

import Account.Hash
import UUID4

import Database.SmplstSQLite3

data Connection = Connection { connCprg :: IORef SystemRNG }

data UserName = UserName BS.ByteString deriving Show
data MailAddress = MailAddress BS.ByteString deriving Show

data MkAccErr = UserNameAlreadyExist | MailAddressAlreadyExist deriving Show
data DeriveError = NoAccount | NotActivated deriving Show

open :: IO Connection
open = Connection <$> (newIORef . cprgCreate =<< createEntropyPool)

stmtMkAccount :: String
stmtMkAccount = "INSERT INTO account (" ++
	"name, salt, hash, mail_address, act_key, activated, is_hbmember) VALUES (" ++
	":name, :salt, :hash, :mail_address, :act_key, 0, :is_hbmember)"

newAccount :: Connection ->
	UserName -> MailAddress -> Password -> IO (Either MkAccErr UUID4)
newAccount conn un@(UserName nm) ma@(MailAddress addr) psw = do
	ne <- checkName un
	ae <- checkAddress ma
	case (ne, ae) of
		(True, _) -> return $ Left UserNameAlreadyExist
		(_, True) -> return $ Left MailAddressAlreadyExist
		_ -> do
			u <- uuid4IO $ connCprg conn
			(Salt slt, Hash hs) <- createHash psw

			_ <- withSQLite "sqlite3/accounts.sqlite3" $ \db ->
				withPrepared db stmtMkAccount $ \sm -> do
					bind sm ":name" $ BSC.unpack nm
					bind sm ":mail_address" $ BSC.unpack addr
					bind sm ":act_key" $ show u
					bind sm ":salt" $ BSC.unpack slt
					bind sm ":hash" $ B64.encode hs
					bind sm ":is_hbmember" (0 :: Int)
					step sm
			return $ Right u

fromRight :: Either a b -> b
fromRight (Right r) = r
fromRight _ = error "fromRight: not Right"

qCheckName :: String
qCheckName = "SELECT name FROM account WHERE name = :name"

checkName :: UserName -> IO Bool
checkName (UserName nm) = withSQLite "sqlite3/accounts.sqlite3" $ \db -> do
	(r, _) <- withPrepared db qCheckName $ \sm -> do
		bind sm ":name" $ BSC.unpack nm
		step sm
	return $ case r of
		Row -> True
		_ -> False

qCheckAddress :: String
qCheckAddress =
	"SELECT mail_address FROM account WHERE mail_address = :mail_address"

checkAddress :: MailAddress -> IO Bool
checkAddress (MailAddress ma) = withSQLite "sqlite3/accounts.sqlite3" $ \db -> do
	(r, _) <- withPrepared db qCheckAddress $ \sm -> do
		bind sm ":mail_address" $ BSC.unpack ma
		step sm
	return $ case r of
		Row -> True
		_ -> False

activate :: UUID4 -> IO ()
activate u = do
	_ <- withSQLite "sqlite3/accounts.sqlite3" $ \db ->
		withPrepared db qSetActivate $ \sm -> do
			bind sm ":act_key" $ show u
			step sm
	return ()

qSetActivate :: String
qSetActivate = "UPDATE account SET activated = 1 where act_key = :act_key"

qSaltHash :: String
qSaltHash = "SELECT salt, hash FROM account WHERE name = :name AND activated = 1"

chkLogin :: UserName -> Password -> IO Bool
chkLogin (UserName n) pw = (fst <$>) . withSQLite "sqlite3/accounts.sqlite3" $ \db ->
	withPrepared db qSaltHash $ \sm -> do
		bind sm ":name" (BSC.unpack n)
		r <- step sm
		print r
		print =<< Hash <$> column sm 1
		print . mkHash pw =<< Salt <$> column sm 0
		case r of
			Row -> chkHash pw
				<$> (Salt <$> column sm 0)
				<*> (Hash . fromRight . B64.decode <$> column sm 1)
			_ -> return False

qGetMailAddress :: String
qGetMailAddress = "SELECT mail_address FROM account WHERE name = :name"

mailAddress :: UserName -> IO (Maybe MailAddress)
	-- (Either DeriveError MailAddress)
mailAddress (UserName nm) = withSQLite "sqlite3/accounts.sqlite3" $ \db ->
	(fst <$>) . withPrepared db qGetMailAddress $ \sm -> do
		bind sm ":name" (BSC.unpack nm)
		r <- step sm
		case r of
			Row -> Just . MailAddress . BSC.pack <$> column sm 0
			_ -> return Nothing

qGetIsHbmember :: String
qGetIsHbmember = "SELECT is_hbmember FROM account WHERE name = :name"

isHbmember :: UserName -> IO Bool
isHbmember (UserName nm) = withSQLite "sqlite3/accounts.sqlite3" $ \db -> do
	(fst <$>) . withPrepared db qGetIsHbmember $ \sm -> do
		bind sm ":name" (BSC.unpack nm)
		r <- step sm
		print r
		column sm 0 >>= (print :: Int -> IO ())
		case r of
			Row -> (== (1 :: Int)) <$> column sm 0
			_ -> return False

qInsertRequest :: String
qInsertRequest =
	"INSERT INTO request(req_id, requester, req_description) " ++
		"VALUES(:req_id, :requester, :req_description)"

insertRequest :: Connection -> UserName -> BS.ByteString -> IO ()
insertRequest conn (UserName nm) r = do
	uu <- uuid4IO $ connCprg conn
	withSQLite "sqlite3/accounts.sqlite3" $ \db -> do
		_ <- withPrepared db qInsertRequest $ \sm -> do
			bind sm ":req_id" $ show uu
			bind sm ":requester" $ BSC.unpack nm
			bind sm ":req_description" $ BSC.unpack r
			step sm
		return ()

qGetRequests :: String
qGetRequests = "SELECT * FROM request"

getRequests :: IO [(BS.ByteString, BS.ByteString, BS.ByteString)]
getRequests = (map (tuple3 BSC.pack) <$>) . withSQLite "sqlite3/accounts.sqlite3" $ \db ->
	(fst <$>) . withPrepared db qGetRequests $ \sm -> doWhile $ do
		r <- step sm
		case r of
			Row -> (Just <$>) $ (\x y z -> (x, y, z))
				<$> column sm 0
				<*> column sm 1
				<*> column sm 2
			_ -> return Nothing

qGetReqDescription :: String
qGetReqDescription =
	"SELECT req_description FROM request WHERE req_id = :req_id"

getReqDescription :: BS.ByteString -> IO (Maybe BS.ByteString)
getReqDescription i = withSQLite "sqlite3/accounts.sqlite3" $ \db ->
	(fst <$>) . withPrepared db qGetReqDescription $ \sm ->  do
		bind sm ":req_id" $ BSC.unpack i
		r <- step sm
		case r of
			Row -> Just <$> column sm 0
			_ -> return Nothing
		
tuple3 :: (a -> b) -> (a, a, a) -> (b, b, b)
tuple3 f (x, y, z) = (f x, f y, f z)

doWhile :: IO (Maybe a) -> IO [a]
doWhile act = do
	r <- act
	case r of Just x -> (x :) <$> doWhile act; _ -> return []

qInsertImage :: String
qInsertImage =
	"INSERT INTO images(img_id, img_request) VALUES(:img_id, :img_request)"

insertImage :: BS.ByteString -> BS.ByteString -> IO ()
insertImage i r = withSQLite "sqlite3/accounts.sqlite3" $ \db -> do
	_ <- withPrepared db qInsertImage $ \sm -> do
		bind sm ":img_id" $ BSC.unpack i
		bind sm ":img_request" $ BSC.unpack r
		step sm
	return ()

qGetImages :: String
qGetImages = "SELECT * FROM images WHERE img_request = :img_request"

getImages :: BS.ByteString -> IO [BS.ByteString]
getImages req = (map BSC.pack <$>) . withSQLite "sqlite3/accounts.sqlite3" $ \db ->
	(fst <$>) . withPrepared db qGetImages $ \sm -> do
		bind sm ":img_request" $ BSC.unpack req
		doWhile $ do
			r <- step sm
			case r of
				Row -> Just <$> column sm 0
				_ -> return Nothing
