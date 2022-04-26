# password-vault
Password vault written in Python, using SQLite (sqlite3) for local database.
The script expects database with a single table, in the form:\

`CREATE TABLE websites (website TEXT PRIMARY KEY, username TEXT NOT NULL, password BLOB NOT NULL)`\
`INSERT INTO websites VALUES("site","username",urlsafe_b64_encoded_password)`\


Necessary imports (aside from sqlite3, you'll need to install command line tools from https://www.sqlite.org/download.html):\
`$pip install pandas`\
`$pip install cryptography`\

# PROTOTYPE ONLY, NOT ACTUALLY SECURE
User inputs a master password which is hashed and stored in the websites table with primary key "password_vault_master". This master password is secure. However, since passwords need to be retrieved, other passwords are encrypted and decrypted with a key using Fernet, and the key is generated by a KDF that takes the master password as input, and this key is stored in the websites table as well with primary key "fernet_key" (which is why this IS NOT SECURE).
The KDF generates a different key for same input which is why the key needs to be stored in the table permanently, but I'm too lazy to figure out a secure place to store this key.

# WARNING
Deleting the fernet_key will make it so that your stored passwords won't be able to be decrypted, so don't delete it. If it's deleted, I've included boilerplate SQL to reset the table (passwords disappear and a new fernet key will be generated when you create new password after resetting)
