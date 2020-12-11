from passlib.hash import argon2
from os import path, mkdir
from getpass import getpass
import secrets
import sys

HOME_DIR = path.expanduser("~")
SALT_DIR = HOME_DIR + "/.pepperpass/"
SALT_FILE = SALT_DIR + "salt.txt"
SALT_LENGTH = 128

PARAMS_FILE = SALT_DIR + "params.txt"


if __name__ == "__main__":

    domain = input("Enter the corresponding domain (strongly recommended): ")
    
    if not path.exists(SALT_DIR):
        try:
            mkdir(SALT_DIR)
        except OSError as error:
            print(error)
    
    if not path.exists(SALT_FILE):
        with open(SALT_FILE, "w") as f:
            f.write(secrets.token_hex(SALT_LENGTH))
    
    if not path.exists(PARAMS_FILE):
        output = ""
        output += (input("digest_size (bytes)") or "32") + "\n"
        output += (input("memory_cost (kibibytes) [press enter for default]") or "512")+ "\n"
        output += (input("rounds [default value: 2]") or "2") + "\n"
        output += (input("parallelism [default value: 2]") or "2") + "\n"
        with open(PARAMS_FILE, "w") as f:
            f.write(output)
    
    with open(SALT_FILE, 'rb') as tmp:
        salt = tmp.read()
    
    with open(PARAMS_FILE, 'r') as tmp:
        params = tmp.readlines()    
    
    h = argon2.using(salt=salt, 
                     digest_size=int(params[0].replace('\n','')), 
                     memory_cost=int(params[1].replace('\n','')),  
                     rounds=int(params[2].replace('\n','')), 
                     parallelism=int(params[3].replace('\n',''))).hash((getpass("Enter your password: ",stream=sys.stderr) or "mickens") + domain)

    print(h.split(',p=')[1].split('$')[2])
