module UserGroup (setUser, setGroup) where

import System.Posix

setUser, setGroup :: String -> IO ()
setUser = (setUserID . userID =<<) . getUserEntryForName
setGroup = (setGroupID . groupID =<<) . getGroupEntryForName
