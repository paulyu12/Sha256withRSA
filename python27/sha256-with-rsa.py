#! /usr/bin/env python2.7
# encoding: utf-8
 
import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA256
import base64
 
def main():
    # private key format: PKCS# 1
    filename = "./userkey.pem"
    testdata = "Hello, sha256 with rsa!"
 
    with open(filename) as f:
        key = f.read()
        prikey = RSA.importKey(key)
        signer = Signature_pkcs1_v1_5.new(prikey)

        digest = SHA256.new()
        digest.update(testdata)

        signature = signer.sign(digest)
    auth_signature = base64.b64encode(signature)     #signature base64
    print "auth_signature: ", auth_signature

    with open("sign.txt", "w") as wf:
        write_size = wf.write(auth_signature)
 
if __name__ == '__main__':
    sys.exit(main())
