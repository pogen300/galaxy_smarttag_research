import logging
import sys

from bluepy.btle import *
from bluepy.btle import DefaultDelegate, Scanner



class WriteDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleNotification(self, cHandle, data):
        print("Received notification from handle: %x" % cHandle)
        print("Data: " + data.hex())

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            logging.info("Discovered device " + dev.addr)
        elif isNewData:
            logging.info("Received new data from " + dev.addr)


def send_cmd(cmd, svc_uuid, char_uuid, handle):
    cmd = bytes.fromhex(cmd)
    scanner = Scanner().withDelegate(ScanDelegate())
    devices = scanner.scan(10.0, passive=True)
    for dev in devices:
        addr = dev.addr
        rssi = dev.rssi
        svc_val = dev.getValueText(2)
        if svc_val == svc_uuid and rssi >= -70:
            print("found smarttag {}, sending commands".format(addr))
            try:
                p = Peripheral(dev, timeout=15).withDelegate(WriteDelegate())
                svc = p.getServiceByUUID(svc_uuid)
                ch = svc.getCharacteristics(char_uuid)[0]
                hnd = ch.getHandle()
                ch.write(cmd, withResponse=False)  
                print("sent command: ", cmd.hex())
                p.disconnect()
            except:
                print("Failed writing characteristic")
                return "Error"
            return

print("Before running this script, please change the value of cmd to an observed playsound command in hex string")
svc_uuid = "0000fd5a-0000-1000-8000-00805f9b34fb"
char_uuid = "dee30001-182d-5496-b1ad-14f216324184"
cmd = "01"
send_cmd(cmd, svc_uuid, char_uuid, 0x58)


