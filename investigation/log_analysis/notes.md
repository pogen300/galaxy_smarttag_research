
# Notes

These subfolders contain data captured using device logging methods via (logcat/HCI snoop log/wireshark)

## ``owner_tag_interaction``

+ ``firmware_update`` the log produced during over-the-air firmware update process
+ ``playsound*.log`` each log contains the data exchange when an Owner device plays sound on a connected SmartTag it owns.
The wireshark filter for viewing the data exchange for playsound:
``
btatt.uuid128 == de:e3:00:01:18:2d:54:96:b1:ad:14:f2:16:32:41:84 && btatt.opcode.method == 0x12
``
+ ``remoteRing*.log``  each contains data exchanged when executing the remote ring command (smarttag rings its owner device)
The wireshark filter for viewing the remote ring commands (encrypted):
``
btatt.uuid128 == de:e3:00:05:18:2d:54:96:b1:ad:14:f2:16:32:41:84
``


## ``registration_ble``
contains the HCI snoop log and partial logcat output produced when registering a SmartTag through the SmartThings app. 

The logcat file contains the UUIDs and names of the characteristics involved in the registration process, and the snoop log file contains the actual data packets being exchanged.


## ``silent_pairing_owner``

**silent-pairing-with-owner-new-04-26-wireshark.pcapng** The silent pairing vulnerability triggered when the SmartThings app attempts to register an impersonated unregistered tag. The device running the impersonation script paired with the target owner device silently.

wireshark filter for viewing the Long Term Key response:
``
bthci_cmd.opcode == 0x201a
``

**silent-pairing-with-owner-registered-04-28-wireshark.pcapng** The silent pairing vulnerability triggered when the SmartThings app attempts to connect to an impersonated registered tag. The device running the impersonation script paired with the target owner device silently.

wireshark filter for viewing the Long Term Key response:
``
bthci_cmd.opcode == 0x201a
``



## ``silent_pairing_tag``

**silent-pairing-with-tag-04-12-wireshark** The silent pairing vulnerability any unauthenticated device can pair with a registered smarttag silently.

wireshark filter for viewing the Long Term Key:
``
btsmp.opcode == 0x06
``
