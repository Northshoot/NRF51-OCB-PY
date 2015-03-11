# NRF51-OCB-PY
A port of OCB implementation for NRF51 using softdevice.
the test.py allows to receive data from uart and decrypt it.
Same py implementation can be used in the cloud, go figure.

Note: there is a Python OCB implementation, however, it supports version 2.
This application supports version 3, hence the usage of the referece code. 

This applicaiton is not suitable for production, not code optimization have been done.

## Usage
Compile shared C library
gcc -o ocb_encrypt_lib.so -shared -fPIC -lcrypto  ocb_shared_lib.c

Compile and upload nrf application
make && nrfjprog program -s /PATH_TO_SDK/s110_nrf51822_7.1.0/s110_nrf51822_7.1.0_softdevice.hex -c _build/nrf51422_xxac.hex


## Copyright
the origial OCB is patented and subject to copyright. Please refere it for usage
http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm

The extention and usage in this project is under License 1 — License for Open-Source Software Implementations of OCB (Jan 9, 2013) 
Under this license, you are authorized to make, use, and distribute open-source software implementations of OCB. This license terminates for you if you sue someone over their open-source software implementation of OCB claiming that you have a patent covering their implementation.

## Links
http://web.cs.ucdavis.edu/~rogaway/ocb/
https://en.wikipedia.org/wiki/OCB_mode

