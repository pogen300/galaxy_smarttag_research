
# (c) 2022 Tingfeng Yu

import dbus, dbus.exceptions, dbus.mainloop.glib
import config
from subprocess import call
import subprocess
import six

try:
    import colorama
    colorama.init()
except ImportError:
    colorama = None

try:
    from termcolor import colored
except ImportError:
    colored = None

def log(string, color, font="slant", figlet=False):
    if colored:
        if not figlet:
            six.print_(colored(string, color))
        else:
            six.print_(colored(figlet_format(
                string, font=font), color))
    else:
        six.print_(string)

# convert a dbus array to bytes
def dbusArray2bytes(arr):
    value = b""
    for i in range(len(arr)):
        value += arr[i].to_bytes(1,'little')
    return value

# convert bytes to a dbus array
def bytes2dbusArray(bytes):
    value = []
    for i in range(len(bytes)):
        value.append(dbus.Byte(bytes[i]))
    return dbus.Array(value, signature=dbus.Signature('y'))

# decrypt an encrypted GATT command
def decryptcommand(ct):
    decrypted_command = config.myclass.decryptCommand(ct.hex())
    return decrypted_command

# encrypt a raw GATT command
def encryptvalue(val):
    ct = config.myclass.encryptCommand(b'',val)
    return bytes2dbusArray(ct)

# change the BLE MAC address of the laptop
def change_mac_address(addr):
    subprocess.run(["./bdaddr", "-i","hci0", addr], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "down"], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "up"], capture_output=True)
    return addr

