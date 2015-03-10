#!/usr/bin/env python

import serial


if __name__ == '__main__':
    print(serial_ports())


def runSerial(speed):
    import serial.tools.list_ports
    for p in list(serial.tools.list_ports.comports()):
        print p
        if 'usbmodem' in p[0]:
            ser = serial.Serial(p[0], speed)
            while True:
                print ser.readline()

if __name__ == '__main__':
    runSerial(38400)