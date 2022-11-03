# -----------------------------------------------------------
# This script was made to impersonate the GATT server of a SmartTag. The GATT server profile contains the following services:
# - Command Service (FD5A)
# - Onboarding Service (FD59)
# - Authentication Service
# - DFU Service (FD5E)
# - Device Info Service
# where each service has a set of characteristics.
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import base64
from time import time

import config
from gatt_advert import Advertisement
from gatt_server import *
from smarttag_crypto import EncryptionPIDManager
from utils import *

GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
ONBOARDING_SVC_UUID = "0000fd59-0000-1000-8000-00805f9b34fb"
TIME_SVC_UUID = "0000fd5a-0000-1000-8000-00805f9b34fb"
AUTH_SVC_UUID = "eedd5e73-6aa8-4673-8219-398a489da87c"
IDENTIFIER_UUID = "08a11e38-1c6d-4929-9c32-4f32a64985ce"
HASHED_SERIAL_NUMBER_UUID = "6ac16db1-f442-4bf4-b804-04c32356465d"
CIPHER_UUID = "50f98bfd-158c-4efa-add4-0a70c2f5df5d"
NONCE_UUID = "a12be31c-5b38-4773-9b9d-3d5735233a7c"
ENONCE_UUID = "4ebe81f6-b952-465e-9ece-5ca39d4e8955"
DFU_SVC_UUID = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CHAR_UUID = "8ec90003-f315-4f60-9fb8-838830daea50"
OWNER_SOUND_UUID = "dee30001-182d-5496-b1ad-14f216324184"
VOLUMN_UUID = "dee30002-182d-5496-b1ad-14f216324184"
REMOTE_RING_UUID = "dee30003-182d-5496-b1ad-14f216324184"
BATTERY_UUID = "dee30004-182d-5496-b1ad-14f216324184"
TIME_UUID = "dee30005-182d-5496-b1ad-14f216324184"
FACTORY_RESET_UUID = "dee30006-182d-5496-b1ad-14f216324184"
BLE_CONNECTION_UUID = "dee3000d-182d-5496-b1ad-14f216324184"
SPEC_VERSION_UUID = "dee3000e-182d-5496-b1ad-14f216324184"
MNMN_UUID = "04052818-d201-43eb-9d81-e936dc86ee06"
VID_UUID = "77b08bec-5890-49d1-b021-811741b417e6"
SELECT_CIPHER_UUID = "6ea31174-87b8-4ff6-98fa-796d87323792"
PRIVACY_SEED_UUID = "d19ddd83-bbe1-4144-bb18-f3ceb57c480a"
PRIVACY_POOL_UUID = "7534c394-1f40-4d12-afd7-dc2a75bd6a44"
OK_UUID = "89b0dfcb-0d9e-42b5-bc98-9a786fdc7d35"
BLE_SC_UUID = "be3a2589-1dfa-4a0a-9429-93899936cbed"
CLOUD_PUBLIC_KEY_UUID = "b5754629-6821-44c6-a118-492feecf6bb2"
REGION_UUID = "bebfaa51-dcb8-44de-a4b8-fc8c9c7ef46d"
FIRMWARE_VERSION_UUID = "30c48d2a-6ccb-4240-9f97-7f97a3f1c030"
CONFIRM_STATUS_UUID = "f299f805-17b3-43c1-ac12-fbcc59ee2f0d"
RANDOM_VALUE_UUID = "d0e8d14e-3d0b-4bda-9dad-4c2790f36210"
MODEL_NAME_UUID = "5352fee4-f3bc-462c-ba7c-279873bcdd71"
PRIVACY_IV_UUID = "abd6e6ba-3843-4786-b9b2-b69548eed881"
SETUP_UUID = "bcc8cce6-8af6-48dc-a0ae-547f7c095229"
SUPPORTED_CIPHER_UUID = "5b5f7a4c-257e-4841-92d5-0042658122b6"
RING_TONE_UUID = "dee3000a-182d-5496-b1ad-14f216324184"
CONFIG_VERSION_UUID = "12761292-241c-490c-8424-6f7cc8a8a027"
tag_nonce = ""
tag_enc_nonce = ""


def register_ad_cb():
    print("Advertisement registered")


def register_ad_error_cb(error):
    print("Failed to register advertisement: " + str(error))
    config.mainloop.quit()


class TagAdvertisement(Advertisement):
    def __init__(self, bus, index, data):
        Advertisement.__init__(self, bus, index, "peripheral")
        self.add_service_uuid(TIME_SVC_UUID)
        data = bytes.fromhex(data)
        self.add_service_data(TIME_SVC_UUID, data)
        self.add_local_name(config.LOCAL_NAME)
        self.include_tx_power = True


class NewTagAdvertisement(Advertisement):
    def __init__(self, bus, index, data):
        Advertisement.__init__(self, bus, index, "peripheral")
        self.add_service_uuid(ONBOARDING_SVC_UUID)
        data = bytes.fromhex(data)
        self.add_service_data(ONBOARDING_SVC_UUID, data)
        self.add_local_name(config.LOCAL_NAME)
        self.include_tx_power = True


class Properties:
    def __init__(self, properties):
        self.read = properties[0]
        self.write = properties[1]
        self.indicate = properties[2]
        self.notify = properties[3]

    def get(self):
        output = []
        if self.read:
            output.append("read")
        if self.write:
            output.append("write-without-response")
        if self.indicate:
            output.append("indicate")
        if self.notify:
            output.append("notify")
        return output


class TagEncCharacteristic(Characteristic):
    def __init__(
        self,
        bus,
        index,
        service,
        char_uuid,
        name: str = "UUID",
        value=dbus.Array([dbus.Byte(1)], signature=dbus.Signature("y")),
    ):
        self.char_uuid = char_uuid
        self.name = name
        Characteristic.__init__(
            self,
            bus,
            index,
            char_uuid,
            ["read", "write-without-response", "indicate", "notify"],
            service,
        )
        self.value = value

    def ReadValue(self, options):
        val = dbusArray2bytes(self.value)
        log(
            "{} (Enc): {} is read: {}".format(self.name, self.char_uuid, val.hex()),
            "green",
        )
        val = bytes2dbusArray(val)
        return val

    def WriteValue(self, value, options):
        v = dbusArray2bytes(value)
        log(
            "{} (Enc): {} is written: {}".format(self.name, self.char_uuid, v.hex()),
            "blue",
        )
        if self.name == "SETUP":
            log(
                "========================== Registration Completed ==========================",
                "green",
            )
            log("Parameters to setup Script 2", "blue")
            log("- Privacy ID IV: {}".format(config.privacy_iv), "blue")
            log("- Privacy ID Seed: {}".format(config.privacy_seed), "blue")
            log("- ECDH Shared Key: {}".format(config.mastersecret), "blue")
        elif self.name == "PRIVACY_SEED":
            base64_bytes = base64.b64encode(v)
            config.privacy_seed = base64_bytes.decode("ascii")
        elif self.name == "PRIVACY_ID_IV":
            base64_bytes = base64.b64encode(v)
            config.privacy_iv = base64_bytes.decode("ascii")

        v = bytes2dbusArray(value)
        self.value = v

    def notify_sth(self):
        val = dbusArray2bytes(self.value)
        log(
            "{} (Enc): {} is notifying: {}".format(
                self.name, self.char_uuid, val.hex()
            ),
            "red",
        )
        val = bytes2dbusArray(val)
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": [val]}, [])
        if self.notifying:
            self.StopNotify()

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True
        self.notify_sth()

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class TagCharacteristic(Characteristic):
    def __init__(
        self,
        bus,
        index,
        service,
        char_uuid,
        name: str = "UUID",
        value=dbus.Array([dbus.Byte(1)], signature=dbus.Signature("y")),
    ):
        self.char_uuid = char_uuid
        self.name = name
        Characteristic.__init__(
            self,
            bus,
            index,
            char_uuid,
            ["read", "write-without-response", "indicate", "notify"],
            service,
        )
        self.value = value

    def ReadValue(self, options):
        log(
            "{}: {} is read: {}".format(
                self.name, self.char_uuid, dbusArray2bytes(self.value).hex()
            ),
            "green",
        )
        return self.value

    def WriteValue(self, value, options):
        v = dbusArray2bytes(value)
        log("{}: {} is written: {}".format(self.name, self.char_uuid, v.hex()), "blue")
        self.value = value

    def notify_sth(self):
        val = dbusArray2bytes(self.value)
        log(
            "{}: {} is notifying: {}".format(self.name, self.char_uuid, val.hex()),
            "red",
        )
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": [self.value]}, [])
        if self.notifying:
            self.StopNotify()

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class NonceCharacteristic(Characteristic):
    def __init__(self, bus, index, service, char_uuid):
        self.char_uuid = char_uuid
        properties = (
            ["encrypt-authenticated-read", "encrypt-authenticated-write", "indicate"]
            if config.is_silent_pairing
            else ["read", "write-without-response", "indicate"]
        )
        Characteristic.__init__(self, bus, index, char_uuid, properties, service)
        self.notifying = False
        self.value = []

    def WriteValue(self, value, options):
        global tag_nonce
        tag_nonce = dbusArray2bytes(value)
        log("Phone -> Tag (nonce) {}".format(tag_nonce.hex()), "blue")
        self.value = bytes2dbusArray(tag_nonce)
        self.notify_sth()

    def ReadValue(self, options):
        print("NONCE Characteristicis read")
        return self.value

    def notify_sth(self):
        global tag_nonce
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": self.value}, [])
        log("Tag -> Phone (nonce): {}".format(tag_nonce.hex()), "red")
        if self.notifying:
            self.StopNotify()

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class ENonceCharacteristic(Characteristic):
    def __init__(self, bus, index, service, char_uuid):
        self.char_uuid = char_uuid
        Characteristic.__init__(
            self, bus, index, char_uuid, ["write-without-response", "indicate"], service
        )
        self.notifying = False
        self.value = []

    def WriteValue(self, value, options):
        global tag_enc_nonce
        tag_enc_noncev = dbusArray2bytes(value)
        log("Phone -> Tag (enonce): {}".format(tag_enc_noncev.hex()), "blue")
        self.value = bytes2dbusArray(tag_enc_noncev)
        self.notify_sth()

    def ReadValue(self, options):
        print("ENONCE Characteristicis read")
        return self.value

    def notify_sth(self):
        log(
            "Tag -> Phone (enonce): {}".format(dbusArray2bytes(self.value).hex()), "red"
        )
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": self.value}, [])
        if self.notifying == True:
            self.StopNotify()

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class TimeCharacteristic(Characteristic):
    def __init__(self, bus, index, service, char_uuid):
        self.char_uuid = char_uuid
        Characteristic.__init__(
            self,
            bus,
            index,
            char_uuid,
            ["read", "write-without-response", "indicate"],
            service,
        )
        self.notifying = False
        cur_time = time()
        arg = int(cur_time).to_bytes(8, byteorder="little")
        arg += bytes.fromhex("84038051010000")
        self.value = arg

    def WriteValue(self, value, options):
        v = dbusArray2bytes(value)
        log("TIME_SYNC {} is written: {}".format(self.char_uuid, v.hex()), "blue")
        if v[0] == bytes.fromhex("00"):
            self.value = bytes2dbusArray(v[1:] + bytes.fromhex("84038051010000"))
            print(dbusArray2bytes(self.value).hex())
        elif v[0] == bytes.fromhex("03"):
            self.notify_sth()

    def notify_sth(self):
        val = dbusArray2bytes(self.value)
        log(
            "TIME_SYNC UUID {} is notifying: {}".format(self.char_uuid, val.hex()),
            "red",
        )
        val = bytes2dbusArray(val)
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": val}, [])
        if self.notifying:
            self.StopNotify()

    def StartNotify(self):
        print("subscribed to Time indication/notification")
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True
        self.notify_sth()

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class RemoteRingCharacteristic(Characteristic):
    def __init__(self, bus, index, service, char_uuid, value):
        self.char_uuid = char_uuid
        Characteristic.__init__(
            self,
            bus,
            index,
            char_uuid,
            ["read", "write-without-response", "indicate"],
            service,
        )
        self.notifying = False
        self.value = value

    def WriteValue(self, value, options):
        log(
            "REMOTE_RING UUID {} is written: {}".format(
                self.char_uuid, dbusArray2bytes(self.value).hex()
            ),
            "blue",
        )

    def notify_sth(self):
        self.value = encryptvalue(b"\x03")
        log(
            "REMOTE_RING UUID {} is notifying: {}".format(
                self.char_uuid, dbusArray2bytes(self.value).hex()
            ),
            "red",
        )
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": self.value}, [])

    def StartNotify(self):
        if self.notifying:
            print("Already notifying, nothing to do")
            return
        self.notifying = True
        self.notify_sth()

    def StopNotify(self):
        if not self.notifying:
            print("Not notifying, nothing to do")
            return
        self.notifying = False


class Tagfd5aService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, TIME_SVC_UUID, True)
        # alarm state
        self.add_characteristic(
            TagEncCharacteristic(
                bus, 0, self, OWNER_SOUND_UUID, "OWNER_SOUND", value=(b"\x00")
            )
        )
        # volume
        self.add_characteristic(
            TagEncCharacteristic(bus, 1, self, VOLUMN_UUID, "VOLUMN", value=(b"\x01"))
        )
        # tagButton
        self.add_characteristic(
            RemoteRingCharacteristic(bus, 2, self, REMOTE_RING_UUID, value=(b"\x02"))
        )
        # battery
        self.add_characteristic(
            TagEncCharacteristic(bus, 3, self, BATTERY_UUID, "BATTERY", value=(b"\x03"))
        )
        self.add_characteristic(TimeCharacteristic(bus, 4, self, TIME_UUID))  # UTC time
        # factory reset
        self.add_characteristic(
            TagEncCharacteristic(bus, 5, self, FACTORY_RESET_UUID, "FACTORY_RESET")
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 6, self, "dee30007-182d-5496-b1ad-14f216324184")
        )
        # ringtone name  'Simple tone 01'
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                7,
                self,
                RING_TONE_UUID,
                "RING_TONE",
                value=(bytes.fromhex("53696d706c6520746f6e65203031")),
            )
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 8, self, "dee3000b-182d-5496-b1ad-14f216324184")
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 9, self, "dee3000c-182d-5496-b1ad-14f216324184")
        )
        # bleConnectionSettings
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                10,
                self,
                BLE_CONNECTION_UUID,
                "BLE_CONNECTION",
                value=(bytes.fromhex("02f700")),
            )
        )
        # spec version 0.5.3
        self.add_characteristic(
            TagCharacteristic(
                bus,
                11,
                self,
                SPEC_VERSION_UUID,
                "SPEC_VERSION",
                value=bytes2dbusArray(bytes.fromhex("01000000302e352e33")),
            )
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 12, self, "dee3000f-182d-5496-b1ad-14f216324184")
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 13, self, "dee30020-182d-5496-b1ad-14f216324184")
        )
        self.add_characteristic(
            TagEncCharacteristic(bus, 14, self, "dee30030-182d-5496-b1ad-14f216324184")
        )


class Tagfd59Service(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, "0000fd59-0000-1000-8000-00805f9b34fb", True)
        # mnmn: Samsung Electronics
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                0,
                self,
                MNMN_UUID,
                "MNMN",
                value=bytes2dbusArray(
                    bytes.fromhex("53616d73756e6720456c656374726f6e696373")
                ),
            )
        )
        # vid: IM-SmartTag-BLE
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                1,
                self,
                VID_UUID,
                "VID",
                value=bytes2dbusArray(bytes.fromhex("494d2d536d6172745461672d424c45")),
            )
        )
        # serialNumber/IDENTIFIER
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                2,
                self,
                IDENTIFIER_UUID,
                "IDENTIFIER",
                value=bytes2dbusArray(bytes.fromhex(config.sn)),
            )
        )
        # hashed serial/identity MAC address
        self.add_characteristic(
            TagCharacteristic(
                bus,
                3,
                self,
                HASHED_SERIAL_NUMBER_UUID,
                "HASHED_SERIAL_NUMBER",
                value=bytes2dbusArray(bytes.fromhex(config.hashed_sn)),
            )
        )
        # configurationVersion: 2.0
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                4,
                self,
                CONFIG_VERSION_UUID,
                "CONFIG_VERSION",
                value=bytes2dbusArray(bytes.fromhex("322e30")),
            )
        )
        # SELECT_CIPHER
        self.add_characteristic(
            TagCharacteristic(bus, 5, self, SELECT_CIPHER_UUID, "SELECT_CIPHER")
        )
        # privacy ID seed
        self.add_characteristic(
            TagEncCharacteristic(bus, 6, self, PRIVACY_SEED_UUID, "PRIVACY_SEED")
        )
        # privacy pool size
        self.add_characteristic(
            TagEncCharacteristic(bus, 7, self, PRIVACY_POOL_UUID, "PRIVACY_POOL")
        )
        # Setup Complete
        self.add_characteristic(TagEncCharacteristic(bus, 8, self, SETUP_UUID, "SETUP"))
        # ?: BUTTON,SERIAL
        self.add_characteristic(
            TagCharacteristic(
                bus,
                9,
                self,
                "b03bd357-034a-4c57-ae56-575d974fc9de",
                "Unknown",
                value=bytes2dbusArray(bytes.fromhex("425554544f4e2c53455249414c")),
            )
        )
        self.add_characteristic(
            TagCharacteristic(bus, 10, self, "b57a3fe1-cf5e-4644-81ab-134d9f8ccaca")
        )
        # ?: OK
        self.add_characteristic(
            TagEncCharacteristic(
                bus,
                11,
                self,
                OK_UUID,
                "OK",
                value=bytes2dbusArray(bytes.fromhex("4f4b")),
            )
        )
        self.add_characteristic(
            TagCharacteristic(bus, 12, self, "661ef3f1-3ac1-483a-9fcb-8014c82bbfae")
        )
        self.add_characteristic(TagCharacteristic(bus, 13, self, BLE_SC_UUID, "BLE_SC"))
        # CLOUD_PUBLIC_KEY
        self.add_characteristic(
            TagCharacteristic(bus, 15, self, CLOUD_PUBLIC_KEY_UUID, "CLOUD_PUBLIC_KEY")
        )
        # region: 12
        self.add_characteristic(
            TagEncCharacteristic(bus, 16, self, REGION_UUID, "REGION")
        )
        # firmware version: 01.01.26
        self.add_characteristic(
            TagCharacteristic(
                bus,
                17,
                self,
                FIRMWARE_VERSION_UUID,
                "FIRMWARE_VERSION",
                value=bytes2dbusArray(bytes.fromhex("30312e30312e3236")),
            )
        )
        # CONFIRM_STATUS
        self.add_characteristic(
            TagEncCharacteristic(bus, 18, self, CONFIRM_STATUS_UUID, "CONFIRM_STATUS")
        )
        # Random Value
        self.add_characteristic(
            TagCharacteristic(bus, 19, self, RANDOM_VALUE_UUID, " RANDOM_VALUE")
        )
        # modelName: EI-T5300
        self.add_characteristic(
            TagCharacteristic(
                bus,
                20,
                self,
                MODEL_NAME_UUID,
                "MODEL_NAME",
                value=bytes2dbusArray(bytes.fromhex("45492d5435333030")),
            )
        )
        self.add_characteristic(
            TagCharacteristic(bus, 21, self, "17bc2035-69ab-4a4f-b41b-7deb18ce6413")
        )
        # privacy ID IV
        self.add_characteristic(
            TagEncCharacteristic(bus, 22, self, PRIVACY_IV_UUID, "PRIVACY_ID_IV")
        )
        # cipher: AES_128-CBC-PKCS7Padding
        self.add_characteristic(
            TagCharacteristic(
                bus,
                23,
                self,
                SUPPORTED_CIPHER_UUID,
                "SUPPORTED_CIPHER",
                value=bytes2dbusArray(
                    bytes.fromhex("4145535f3132382d4342432d504b43533750616464696e67")
                ),
            )
        )


class TagDFUService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, DFU_SVC_UUID, True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, DFU_CHAR_UUID, "BUTTONLESS_DFU")
        )  # Buttonless DFU characteristic


class TagAuthService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, AUTH_SVC_UUID, True)
        self.add_characteristic(
            NonceCharacteristic(bus, 0, self, NONCE_UUID)
        )  # nonce characteristic (r w i)
        self.add_characteristic(
            ENonceCharacteristic(bus, 1, self, ENONCE_UUID)
        )  # encrypted nonce characteristic (w i)
        self.add_characteristic(TagCharacteristic(bus, 2, self, CIPHER_UUID, "CIPHER"))


class DeviceInfoService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, "180a", True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, "2a29", value="SOLUM")
        )  # Manufacturer name string
        self.add_characteristic(
            TagCharacteristic(bus, 1, self, "2a26", value="1.0126")
        )  # FWRevisionString
        self.add_characteristic(
            TagCharacteristic(bus, 2, self, "2a28", value="2")
        )  # SWRevisionString
