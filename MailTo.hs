{-# LANGUAGE OverloadedStrings #-}

module MailTo (mailTo) where

import Network.Mail.SMTP (Address(..), sendMail, simpleMail, plainTextPart)
import UUID4 (UUID4)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT

mailTo :: BS.ByteString -> UUID4 -> IO ()
mailTo to ui = sendMail "skami2.iocikun.jp" . simpleMail
			(Address (Just "Homepage") "tatsuya@skami.iocikun.jp")
			[Address (Just "Administrator")
				(toAt . T.pack $ BSC.unpack to)] [] []
			(T.pack "HummingBird") . (: []) . plainTextPart . LT.pack $ "アカウントを作成します: \n\nhttps://skami2.iocikun.jp/activate?activation_key=" ++ show ui

toAt :: T.Text -> T.Text
toAt bs = case T.splitAt 3 bs of
	("%40", bs') -> T.cons '@' $ toAt bs'
	_ -> case T.uncons bs of
		Just (c, bs') -> T.cons c $ toAt bs'
		_ -> ""
-- toAt ('%' : '4' : '0' : s) = '@' : s
-- toAt (c : s) = c : toAt s
