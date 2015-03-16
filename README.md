# NRF51-OCB-PY
A port of OCB implementation for NRF51 using softdevice.
the test.py allows to receive data from uart and decrypt it.
Same py implementation can be used in the cloud, go figure.

Note: there is a Python OCB implementation, however, it supports only version 2.
This application supports version 3, hence python example uses ctypes to speed-up crypto and reuses same (ok, almost the same) c implementaiton as on node. 

This applicaiton is not suitable for production, not code optimization have been done.

## Getting
You need to include submodules as well. I desided to fork and clean tinyAES to minimize the code size. We have only AES ECB mode hence, the other mode not needed. The NRF51 provides encryption, hence we need only soft decrypt

```bash
git clone --recursive https://github.com/Northshoot/NRF51-OCB-PY.git
```

## Usage
Compile shared C library
```bash
gcc -o ocb_encrypt_lib.so -shared -fPIC -lcrypto  ocb_shared_lib.c
```

Compile and upload nrf application
```bash
make && nrfjprog program -s /PATH_TO_SDK/s110_nrf51822_7.1.0/s110_nrf51822_7.1.0_softdevice.hex -c _build/nrf51422_xxac.hex
```
## tests

Security test zero vectors		

| data size bytes|	encrypt (HW-AES) ms |	decrypt (SW_AES) ms |	ration SW/HW |
| ------------- |:-------------:| -----:|  -----:|
| 32 |	0.969 |	1.594 |	1.64 |
| 64 |	1.53 |	3.656 |	2.39 |
| 128 |	2.594 |	9.25 |	3.57 |
| 256	| 5.219	| 18.281 |	3.50 |
| 512	| 10.062 |	34.906 |	3.47 |
| 1024 |	19.031 |	69.406 | 3.65 |
| 2048 |	36.25 |	138.562 |	3.82 |
| 4096 |	70.688 |	276.969 |	3.92 |


## needed improvements
### Dynamic array length:


right now these values in C library
```c
#define KEYSIZE  16
#define DATASIZE  32
#define TAGSIZE  16
#define CIPHERSIZE  DATASIZE+TAGSIZE
```

must be same and manualy edited as in python

```python
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
```        
would be nice to have "automagical" allocation


## Copyright
the origial OCB is patented and subject to copyright. Please refere it for usage
http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm

The extention and usage in this project is under License 1 — License for Open-Source Software Implementations of OCB (Jan 9, 2013) 
Under this license, you are authorized to make, use, and distribute open-source software implementations of OCB. This license terminates for you if you sue someone over their open-source software implementation of OCB claiming that you have a patent covering their implementation.

## Links
http://web.cs.ucdavis.edu/~rogaway/ocb/
https://en.wikipedia.org/wiki/OCB_mode

## Thanks
Huge thanks for Henry & Neil for giving ideas in the dark moments!
