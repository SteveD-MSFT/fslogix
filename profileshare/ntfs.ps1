icacls <mounted-drive-letter>: /grant <user-email>:(M)
icacls <mounted-drive-letter>: /grant "Creator Owner":(OI)(CI)(IO)(M)
icacls <mounted-drive-letter>: /remove "Authenticated Users"
icacls <mounted-drive-letter>: /remove "Builtin\Users"