#!/usr/bin/python
# -*- coding: UTF-8 -*-
__author__="GrantLi"
__version__="0.1.0"

import socket
import time
import sys

class EspTouch_smartconfig():
    def __init__(self):
        self.ipBytes = None
        self.ssidBytes = None
        self.passwordBytes = None
        self.data = None
        self.dataToSend = []
        self.addressCount = 0
        self.sendBuffer = bytearray(600)

        if len(sys.argv) > 3:
            self.wifi_settings(sys.argv[1], sys.argv[2], sys.argv[3])
            for i in range(0, 4):
                self.sendData()
        # elif len(sys.argv) > 4:
        #     self.wifi_settings(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], None)
        #     for i in range(0, 4):
        #         self.sendData()
        else:
            print("Usage : ESPTouch.py [ssid] [password] [returnIP] ")
            pass


    def wifi_settings(self, _ssid, _password, _ip):
        _bssid = None
        if _bssid:
            self.bssidBytes = bytes.fromhex(_bssid)
        else:
            self.bssidBytes = bytes()
        self.ssidBytes = bytes(_ssid.encode())
        self.passwordBytes = bytes(_password.encode())
        self.ipBytes = bytes(map(int, _ip.split('.')))
        self.useBroadcast = True
        if len(self.ipBytes) != 4:
            raise ValueError("IP address invalid")
        # Data is ip (4 bytes) + password 
        self.data = self.ipBytes + self.passwordBytes
        # + ssid if hidden but this is not enforced on Android..... so we always include it as well
        self.data += self.ssidBytes
    #    print("DATA length", len(data))
    #    print("DATA-->", ":".join("{:02x}".format(c) for c in data))
    #    print("bssid-->", ":".join("{:02x}".format(c) for c in bssidBytes))
    #    print("ssid-->", ":".join("{:02x}".format(c) for c in ssidBytes))
    #    print("Broadcast--> {}".format(useBroadcast))


    def getClientSocket(self):
        sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        if self.useBroadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        return sock

    def sendPacket(self, _socket, _destination, _size):
        if isinstance(_socket, socket.socket) is not True:
            raise ValueError("sendPacket error invalid socket object")
    #    print("{}  Sending {} bytes to {}".format(time.monotonic(), len(sendBuffer[0:_size]), _destination))
        _socket.sendto(self.sendBuffer[0:_size], _destination)

    def getNextTargetAddress(self):
        if self.useBroadcast:
            return ("255.255.255.255", 7001)
        else:
            self.addressCount += 1
            multicastAddress = "234.{}.{}.{}".format(self.addressCount, self.addressCount, self.addressCount)
            self.addressCount %= 100
            return (multicastAddress, 7001)

    def AddToCRC(self, b, crc):
        if (b < 0):
            b += 256
        for i in range(8):
            odd = ((b^crc) & 1) == 1
            crc >>= 1
            b >>= 1
            if (odd):
                crc ^= 0x8C # this means crc ^= 140
        return crc

    # one data format:(data code should have 2 to 65 data)
    # 
    #              control byte       high 4 bits    low 4 bits
    # 1st 9bits:       0x0             crc(high)      data(high)
    # 2nd 9bits:       0x1                sequence header
    # 3rd 9bits:       0x0             crc(low)       data(low)
    # 
    def encodeDataByte(self, dataByte, sequenceHeader):
        if sequenceHeader > 127 :
            raise ValueError('sequenceHeader must be between 0 and 127')
        # calculate the crc
        crc = 0
        crc = self.AddToCRC(dataByte, crc)
        crc = self.AddToCRC(sequenceHeader, crc)
        # split in nibbles
        crc_high, crc_low = crc >> 4, crc & 0x0F
        data_high, data_low = bytes([dataByte])[0] >> 4, bytes([dataByte])[0] & 0x0F
        # reassemble high with high , low with low and add 40
        first = ((crc_high << 4) | data_high) + 40
        # second ninth bit must be set (256 + 40)
        second = 296 + sequenceHeader
        third = ((crc_low << 4) | data_low) + 40
        return (first, second, third)

    def getGuideCode(self):
        return (515, 514, 513, 512)

    def getDatumCode(self):
        totalDataLength = 5 + len(self.data)
        passwordLength = len(self.passwordBytes)
        ssidCrc = 0
        for b in self.ssidBytes:
            ssidCrc = self.AddToCRC(b, ssidCrc)
        bssidCrc = 0
        for b in self.bssidBytes:
            bssidCrc = self.AddToCRC(b, bssidCrc)
        totalXor = 0
        totalXor ^= totalDataLength
        totalXor ^= passwordLength
        totalXor ^= ssidCrc
        totalXor ^= bssidCrc
        for b in self.data:
            totalXor ^= b
        return (totalDataLength, passwordLength, ssidCrc, bssidCrc, totalXor)

    def getDataCode(self):
        return (self.data)

    def prepareDataToSend(self):
        # human readable data in the console in pack of three bytes
    #    i = 0
    #    for b in getDatumCode():
    #        print(encodeDataByte(b, i))
    #        i += 1
    #    iBssid = len(getDatumCode()) + len(getDataCode())
    #    bssidLength = len(bssidBytes)
    #    indexBssid = 0
    #    indexData = 0
    #    for b in getDataCode():
    #        # add a byte of the bssid every 4 bytes
    #        if (indexData % 4) == 0 and indexBssid < bssidLength:
    #            print(encodeDataByte(bssidBytes[indexBssid], iBssid))
    #            iBssid += 1
    #            indexBssid += 1
    #        print(encodeDataByte(b, i))
    #        i += 1
    #        indexData += 1
    #    while indexBssid < bssidLength:
    #        print(encodeDataByte(bssidBytes[indexBssid], iBssid))
    #        iBssid += 1
    #        indexBssid += 1
        # The data
        i = 0
        for d in self.getDatumCode():
            for b in self.encodeDataByte(d, i):
                self.dataToSend += [b]
            i += 1
        iBssid = len(self.getDatumCode()) + len(self.getDataCode())
        bssidLength = len(self.bssidBytes)
        indexBssid = 0
        indexData = 0
        for d in self.getDataCode():
            # add a byte of the bssid every 4 bytes
            if (indexData % 4) == 0 and indexBssid < bssidLength:
                for b in self.encodeDataByte(self.bssidBytes[indexBssid], iBssid):
                    self.dataToSend += [b]
                iBssid += 1
                indexBssid += 1
            for b in self.encodeDataByte(d, i):
                self.dataToSend += [b]
            i += 1
            indexData += 1
        while indexBssid < bssidLength:
            for b in self.encodeDataByte(self.bssidBytes[indexBssid], iBssid):
                self.dataToSend += [b]
            iBssid += 1
            indexBssid += 1

    def sendGuideCode(self):
        index = 0
        destination = self.getNextTargetAddress()
        # run for 2 sec send packet every 8 msec
        nexttime = now = time.monotonic()
        endtime = now + 2
        while now < endtime or index != 0:
            now = time.monotonic()
            if now > nexttime:
                self.sendPacket(self.getClientSocket(), destination, self.getGuideCode()[index]) 
                nexttime = now + 0.008
                index += 1
                if index > 3:
                    destination = self.getNextTargetAddress()
                index %= 4

    def sendDataCode(self):
        index = 0
        destination = self.getNextTargetAddress()
        # run for 4 sec send packet every 8 msec
        nexttime = now = time.monotonic()
        endtime = now + 4
        while now < endtime or index != 0:
            now = time.monotonic()
            if now > nexttime:
                self.sendPacket(self.getClientSocket(), destination, self.dataToSend[index]) 
                nexttime = now + 0.008
                index += 1
                if (index % 3) == 0:
                    destination = self.getNextTargetAddress()
                index %= len(self.dataToSend)

    def sendData(self):
    #    print("DATUM: ", getDatumCode())
    #    print("GUIDE: ", getGuideCode())
        self.prepareDataToSend()
        print("Sending data...")
        self.sendGuideCode()
        self.sendDataCode()
        print("Done!")


if __name__ == "__main__":
    EspTouch_smartconfig()


