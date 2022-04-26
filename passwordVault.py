import sqlite3
import os
import pandas as pd
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import hashlib
import base64

conn = sqlite3.connect("passwords.db")
cur = conn.cursor()
m = hashlib.sha256()

def quickExit(entry): #helper method for checking if user made an input mistake
    if entry.lower() == 'q':
        return True
    
    return False

def execSQL(query, conn):
#supposed to be used for clarity, but not really used since
#I need the cursor's returned value (and the execution is just 2 lines long)
  cur.execute(query)
  conn.commit()

def checkNewUser():
    cur.execute('SELECT * FROM websites WHERE website="password_vault_master"')
    conn.commit()
    data = cur.fetchone() #data in form of tuple (website, username, password)
    if data == None:
        master_password = ''
        confirm_password = '1'

        while master_password != confirm_password:
            master_password = input('You are a new user! Please enter a master password: ').strip()
            confirm_password = input('Confirm password: ').strip()
            if master_password != confirm_password:
                print('Passwords did not match, please try again.')


        m.update(master_password.encode('utf8')) #hash new master password and upload to DB
        cur.execute('INSERT INTO websites VALUES(?,?,?)',("password_vault_master","master",m.digest()))
        conn.commit()
        return master_password #returns unhashed master password for key for encryption
    else:
        master_password = data[2] #hashed password
        check = ''
        temp = ''
        while check != master_password: #hash entered password so it matches hashed master password
            n = hashlib.sha256()
            input_pass = getpass('Enter master password: ').strip()
            temp = input_pass
            n.update(input_pass.encode('utf8'))
            check = n.digest()

        return temp #returns unhashed master password for key for encryption

def checkForbiddenSites(site):
    if site == 'fernet_key' or site == "password_vault_master" or site == "all":
        print('Forbidden.')
        return True
    else:
        return False

def getKey(key):
    """
    Check if there exists a fernet key entry, if not then the user is new and we must create a new entry
    Otherwise, we just need to grab the existing fernet key
    """
    cur.execute('SELECT * FROM websites WHERE website="fernet_key"')
    conn.commit()
    data = cur.fetchone()
    if data == None:
        cur.execute('INSERT INTO websites VALUES(?,?,?)',("fernet_key","fernet_user",key))
        conn.commit()
        return key
    else:
        return data[2]

def accessPassword(fernet):
    site = input('Enter website name you are trying to retrieve: ').strip().lower()
    if checkForbiddenSites(site):
        return None 

    if quickExit(site):
        return

    query = 'SELECT * FROM websites WHERE website="{site}"'.format(site=site)
    res = pd.read_sql_query(query,conn) #read query

    if res.empty == True:
        print('No such website.\n')
        return

    print('Requested Data:')
    # pylint: disable=fixme, no-member
    data = res.at[0, 'password'] #get first returned data's password entry
    res.at[0,'password'] = fernet.decrypt(data).decode('ascii') #decrypt then decode password
    print(res)
    print()

def updatePassword(fernet):
    site = input('Enter website name you are trying to update: ').strip().lower()

    if checkForbiddenSites(site): #makes sure entered website is not a forbidden one
        return
        
    if quickExit(site): #check for quick exit
        return

    action = int(input('Enter 1 to update password, enter 2 to update username: ').strip())

    if quickExit(action): #check for quick exit
        return

    if action == 2:
        new_username = input('Enter new username: ').strip()
        cur.execute('UPDATE websites SET username=? WHERE website=?',(new_username,site))
        conn.commit()
        print('Updated username for {site}'.format(site=site))
        print()
        return

    new_password = getpass('Enter new password: ').strip()
    confirm_password = ''
    while confirm_password != new_password: #check password
        confirm_password = getpass('Confirm password: ').strip()

    to_insert = fernet.encrypt(new_password.encode('ascii')) #encode then encrypt password

    """
    execute command this way or else data will be stored as string and not bytes,
    because if stored as string we can't decrypt on accessPassword's end
    """
    cur.execute('UPDATE websites SET password=? WHERE website=?',(to_insert,site))
    conn.commit()
    #query = 'UPDATE websites SET password={to_insert} WHERE website="{site}"'.format(to_insert=to_insert,site=site)
    #execSQL(query, conn) #update websites table by setting password where website is site
    print('Updated password for {site}'.format(site=site))
    print()


def createPassword(fernet):
    site = input('Enter new website name: ').strip().lower()
    if checkForbiddenSites(site): #makes sure entered website is not a forbiddeon one
        return

    if quickExit(site):
        return

    username = input('Enter username/email: ').strip()  
    new_password = getpass('Enter new password: ').strip()

    if quickExit(username) or quickExit(new_password):
        return

    confirm_password = ''
    while confirm_password != new_password: #check password
        confirm_password = getpass('Confirm password: ').strip()

    to_insert = fernet.encrypt(new_password.encode('ascii')) #encode then encrypt password  
    cur.execute('INSERT INTO websites VALUES(?,?,?)', (site, username, to_insert))
    conn.commit()
    print('Created entry for {site}\n'.format(site=site))

def deletePassword():
    site = input('Enter website name you are trying to delete: ').strip()
    if checkForbiddenSites(site): #makes sure entered website is not a forbidden one
        return

    if quickExit(site):
        return

    query = 'DELETE FROM websites WHERE website = "{site}"'.format(site=site)
    cur.execute(query)
    conn.commit()
    print('Deleted entry for {site}\n'.format(site=site))

def listAllSites():

    query = 'SELECT website FROM websites WHERE website<>"password_vault_master" AND website<>"fernet_key"'
    res = pd.read_sql_query(query, conn)
    print('Requested Data: ')
    print(res)
    print()

if __name__ == "__main__":

    backend = default_backend() #cryptography stuff
    salt = os.urandom(16)

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=backend
    )

    """ Boilerplate to reset table
    execSQL('ALTER TABLE websites RENAME to websites_old',conn)
    execSQL('CREATE TABLE websites (website TEXT PRIMARY KEY, username TEXT NOT NULL, password BLOB NOT NULL)',conn)
    execSQL('DROP TABLE websites_old',conn)
    """

    """Encryption steps:
    1. Grab password as string
    2. Encode password and pass as input to key derivation function to generate a temp key
    3. Encode it as b64 and make it url safe
    4. This is a new key, it is newly generated each time the program runs. We pass it into 
    the getKey() function, which checks if a key already exists in the DB, if it does we just
    return the one in the database as that is the one that will allow us to decrypt the stored
    passwords. If not we will be unable to decrypt any of the passwords stored in the table
    5. We now have the key, and pass it into the Fernet class to create a fernet instance for
    encryption and decryption
    """
    master_pass = checkNewUser()
    temp_key = kdf.derive(master_pass.encode())
    newKey = base64.urlsafe_b64encode(temp_key)

    key = getKey(newKey)
    fernet = Fernet(key)

    print('-----------------------WELCOME----------------------\n')
    print('1: Access username and password for existing website\n')
    print('2: Change/update username or password for existing website\n')
    print('3: Create new username and password for new website\n')
    print('4: Delete data for existing website\n')
    print('5: List all websites\n')
    print('0: Quit\n')

    while True: #loop forever so that u only quit after ur done with all tasks 

        action = -1 #initialize action
        valid_action_flag = False
        while not valid_action_flag: #ensure inputted number is a valid action
            try:
                action = int(input('What would you like to do? Enter number corresponding to action: '))
            except ValueError:
                print('Please enter an integer for action')
            if action == 1 or action == 2 or action == 3 or action == 4 or action == 5 or action == 0:
                valid_action_flag = True
            else:
                print('Not a valid action, please try again.')

        if action == 1:
            accessPassword(fernet)
        elif action == 2:
            updatePassword(fernet)
        elif action == 3:
            createPassword(fernet)
        elif action == 4:
            deletePassword()
        elif action == 5:
            listAllSites()
        elif action == 0:
            print('Goodbye.\n')
            break






