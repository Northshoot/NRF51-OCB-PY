#!/usr/bin/python
# this file is implementation of OCB in Python
# used to test NRF51 OCB encryption
# and end to end transmisison + decrypt
# pip install pyocb


from ocb.aes import AES
from ocb import OCB
import binascii



if __name__ == "__main__":
    aes = AES(128)
    ocb = OCB(aes)
    key = bytearray().fromhex('000102030405060708090a0b0c0d0e0f')
    ocb.setKey(key)
    
    nonce = bytearray().fromhex('00000000000000000000000000000001')
    
    ocb.setNonce(nonce)
    plaintext = bytearray().fromhex('000102') #bytearray('The Magic Words are Squeamish Ossifrage')
    header = bytearray(b'')
    (tag,ciphertext) = ocb.encrypt(plaintext, header)
    print("TAG: ", binascii.hexlify(tag))
    print("DTA: ",binascii.hexlify(ciphertext))
    
    #Encryption will reset _nonce_ status, so that it needs to be set to a new value.
    
    # Decryption
    #----------
    ocb.setNonce(nonce)
    (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
    print( is_authentic )
    print( binascii.hexlify(plaintext2) )
    

