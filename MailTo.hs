{-# LANGUAGE OverloadedStrings #-}

module MailTo (mailTo) where

import Data.Maybe (fromMaybe)
import Network.Mail.SMTP (Address(..), sendMail, simpleMail, plainTextPart)
import UUID4 (UUID4)

import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT

mailTo :: String -> UUID4 -> IO ()
mailTo to ui = sendMail "skami2.iocikun.jp" . simpleMail
			(Address (Just "Homepage") "tatsuya@skami.iocikun.jp")
			[Address (Just "Administrator") (T.pack $ toAt to)] [] []
			(T.pack "HummingBird") . (: []) . plainTextPart . LT.pack $ "アカウントを作成します: \n\nhttps://skami2.iocikun.jp/activate?activation_key=" ++ show ui

toAt :: String -> String
toAt ('%' : '4' : '0' : s) = '@' : s
toAt (c : s) = c : toAt s
