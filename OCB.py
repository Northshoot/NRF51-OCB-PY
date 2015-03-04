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
    key = bytearray().fromhex('41414141414141414141414141414141')
    ocb.setKey(key)

    nonce = bytearray().fromhex('00000000000000000000000000000000')

    ocb.setNonce(nonce)
    plaintext = bytearray().fromhex('02020101010101010101010101010101') #bytearray('The Magic Words are Squeamish Ossifrage')
    header = bytearray().fromhex('00000000000000000000000000000000')
    (tag,ciphertext) = ocb.encrypt(plaintext, header)
    print("TAG: ", binascii.hexlify(tag))
    print("DTA: ",binascii.hexlify(ciphertext))

    #Encryption will reset _nonce_ status, so that it needs to be set to a new value.

    # Decryption
    #----------
    ocb.setNonce(nonce)
    (is_authentic, plaintext2) = ocb.decrypt(header, ciphertext, tag)
    print( is_authentic )
    print( str(plaintext2))

    #The flag will be set to _False_ and plaintext will be empty if ciphertext is modified:

    ciphertext[3] = 0
    print(ocb.decrypt(header, ciphertext, tag))
    #The same happens if header is modified (even ciphertext was not):

