{-# LANGUAGE OverloadedStrings #-}

module MailTo (mailTo) where

import Data.Maybe (fromMaybe)
import Network.Mail.SMTP (Address(..), sendMail, simpleMail, plainTextPart)

import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT

mailTo :: String -> IO ()
mailTo to = sendMail "skami2.iocikun.jp" . simpleMail
			(Address (Just "Homepage") "tatsuya@skami.iocikun.jp")
			[Address (Just "Administrator") (T.pack $ toAt to)] [] []
			(T.pack "HummingBird") . (: []) . plainTextPart . LT.pack $ "アカウントを作成しました"

toAt :: String -> String
toAt ('%' : '4' : '0' : s) = '@' : s
toAt (c : s) = c : toAt s
