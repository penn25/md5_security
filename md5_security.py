from Crypto.Cipher import AES
import base64
import os

class MD5Security:
    
    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: encypt_cipher
    # DESCRIPTION : This will create cipher
    # DATE CREATED: 04/18/2018
    #------------------------------------------------------

    def encypt_cipher(self, secret_key):

        # CREATE CIPHER
        cipher = AES.new(secret_key,AES.MODE_ECB)

        return cipher

    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: decrypt_cipher
    # DESCRIPTION : This will create cipher
    # DATE CREATED: 04/18/2018
    #------------------------------------------------------

    def decrypt_cipher(self, secret_key):
        
        # CREATE CIPHER
        cipher = AES.new(secret_key)
        
        return cipher

    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: encryption
    # DESCRIPTION : This will encrypt your string
    # DATE CREATED: 04/18/2018
    # NOTE : AES key must be either 16, 24, or 32 bytes long
    #        SET AT LEAST 16 CHARACTER FOR secret_key VALUE
    #------------------------------------------------------

    def encryption(self, private_info, secret_key='1080pFullHD20188', PADDING='{', BLOCK_SIZE=16):

        # INIT 
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

        # GET THE CIPHER
        cipher = self.encypt_cipher(secret_key)

        # ENCRYPT
        encoded = EncodeAES(cipher, private_info)

        return encoded

    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: decryption
    # DESCRIPTION : This will decrypt your string
    # DATE CREATED: 04/18/2018
    # NOTE : AES key must be either 16, 24, or 32 bytes long
    #        SET AT LEAST 16 CHARACTER FOR secret_key VALUE
    #------------------------------------------------------

    def decryption(self, private_info, secret_key='1080pFullHD20188', PADDING='{'):

        try:
            # INIT 
            DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

            # GET THE CIPHER
            cipher = self.decrypt_cipher(secret_key)

            # DECRYPT
            decoded = DecodeAES(cipher, private_info)

        except:

            # RETURN UNDECODE
            decoded = private_info

        return decoded

    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: key_encryptor
    # DESCRIPTION : This will encrypt keys in json
    # DATE CREATED: 04/18/2018
    #------------------------------------------------------
  
    def key_encryptor(self, json_data, keys):
        
        # INIT
        final_data = {}

        # LOOP JSON DATA
        for key,value in json_data.iteritems():
            
            # FIND KEYS
            if key in keys:
                
                # ENCRYPT VALUE
                value = self.encryption(value)
            
            # SET VALUE
            final_data[key] = value 

        return final_data

    #------------------------------------------------------
    # AUTHOR : KRISFEN G. DUCAO
    # FUNCTION: key_decryptor
    # DESCRIPTION : This will encrypt keys in json
    # DATE CREATED: 04/18/2018
    #------------------------------------------------------
  
    def key_decryptor(self, json_data, keys):
        
        # INIT
        final_data = []

        # LOOP JSON DATA
        for json_dict in json_data:
            
            new_json_data = {}
            for key,value in json_dict.iteritems():
            
                # FIND KEYS
                if key in keys:
                    # DECRYPT VALUE
                    value = self.decryption(value)
            
                # SET VALUE
                new_json_data[key] = value 
            final_data.append(new_json_data)   

        return final_data

