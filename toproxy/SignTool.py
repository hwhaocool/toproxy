#coding:utf-8

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import base64
import hashlib

class SignTools:

    __signer = None

    def __init__(self, *args, **kwargs):
        """构造方法"""
        f = open("rsa_private_pkcs8_key.pem", "r")
        private_key_str = f.readlines()

        pri_key = RSA.importKey(private_key_str)
        self.__signer = PKCS1_v1_5.new(pri_key)

    def sign(self, data):
        """对数据进行签名"""
        
        hash_obj = SHA.new(data)
        sign_result =  self.__signer.sign(hash_obj)
        return base64.b64encode(sign_result)

if __name__ == '__main__':
    s = SignTools()
    b = s.sign("hello")
    print(b)