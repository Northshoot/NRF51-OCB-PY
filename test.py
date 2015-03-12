#!/usr/bin/env python

import serial
import time
import struct
from ctypes import *

def runSerial(BAUD, size=16):
    import serial.tools.list_ports
    PORT =''
    NAME =''
    for p in list(serial.tools.list_ports.comports()):
        if 'usbmodem' in p[0]:
            PORT = p[0]
            NAME = p[1]
            break
    if PORT:
        ser = serial.Serial(PORT, BAUD)
        ser.setDTR(level=False)
        time.sleep(0.5)
        # ensure there is no stale data in the buffer
        ser.flushInput()
        ser.setDTR()
        time.sleep(0.5)
        print( "waiting for NRF %s..." %NAME )

        s = struct.Struct('16B')
        read_byte = ser.read()
        while True:
            print  s.unpack_from(ser.readline())
            print "              "


KEYSIZE = 16
DATASIZE = 32
TAGSIZE = 16
CIPHERSIZE = DATASIZE+TAGSIZE
KEYBYTES = c_uint8*KEYSIZE
DATABYTES = c_uint8*DATASIZE
CIPHERBYTES = c_uint8 * CIPHERSIZE

class EncryptedData(Structure):
    _fields_ = [
        ("datalength", c_uint32),
        ("key", KEYBYTES),
        ("nonce", KEYBYTES),
        ("assoc", DATABYTES),
        ("cipher", CIPHERBYTES),
        ("cleartext", DATABYTES)]

if __name__ == '__main__':
    #    try:
    #        runSerial(38400)
    #    except KeyboardInterrupt:
    #        print("")
    #        print("Exiting")
    #    except Exception as e:
    #        print e

    from ctypes import cdll
    import sys
    # load the library

    encrypt_lib = cdll.LoadLibrary("ocb_encrypt_lib.so")
    encrypt = encrypt_lib.py_ocb_encrypt #connet function
    decrypt = encrypt_lib.py_ocb_decrypt #connect functions
    encrypt.argtypes = [POINTER(EncryptedData)] # create arg type
    encrypt.restype = c_int
    #### test for encryption
    data_pkt = EncryptedData(DATASIZE) # creat in data strcuture
    data_pkt.key= (KEYBYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    data_pkt.nonce= (KEYBYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

    data_pkt.assoc = (DATABYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

    array_type = DATABYTES
    data = array_type()
    for i in range(DATASIZE):
        data[i]= 0
    data_pkt.cleartext = data
    # bam execute
    print 'encrypt returned =', encrypt(byref(data_pkt))
    print 'BlockLength =', data_pkt.datalength
    for i,b in enumerate(data_pkt.cipher):
        sys.stdout.write('%d, ' %b)
    sys.stdout.write('\n')

    #### test for decrypt
    data_pkt_decrypt = EncryptedData(DATASIZE)
    data_pkt_decrypt.key= (KEYBYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    data_pkt_decrypt.nonce= (KEYBYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    data_pkt_decrypt.assoc = (DATABYTES)(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    data_pkt_decrypt.cipher = data_pkt.cipher
    # all 32 x 0 test vector
    # data_pkt.cipher= (CIPHERBYTES)(253, 67, 171, 248, 217, 15, 51, 20,
    #                               70, 255, 24, 201, 14, 97, 71, 34,
    #                               226, 84, 18, 25, 93, 233, 88, 195,
    #                               48, 119, 182, 179, 61, 74, 89, 97,
    #                               200, 38, 216, 241, 52, 246, 130, 246,
    #                               196, 82, 209, 184, 238, 36, 225, 26)

    print 'decrypt returned =',decrypt(byref(data_pkt_decrypt))
    print 'BlockLength =',data_pkt_decrypt.datalength
    for i,b in enumerate(data_pkt_decrypt.cleartext):
        sys.stdout.write('%d, ' %b)
    sys.stdout.write('\n')
