import qualified Account.Database as DB

main :: IO ()
main = newTable

newTable :: IO ()
newTable = do
	conn <- DB.open
	DB.mktRequest conn
	DB.close conn
