# -----------------------------------------------------------
# This script gets the token(s) required for an Samsung account owner to access SmartThings web services
# Run it to set up the bearer token for script6 (automated tag registration for an adversary)
# and script7 (automated location pulling for an owner)
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import requests
from utils import *
import json
import argparse
import pprint
physical_address_text = None
signin_client_id = None
client_id = None

def load_user_info(i):
    f = open('user_info.json')
    users = json.load(f)["users"]
    user = users[i]
    print("Loaded credentials for user ",i)
    return user

def save_user_info(user, i):
    f = open('user_info.json')
    data = json.load(f)
    data["users"][i] = user
    with open('user_info.json', 'w') as f:
        json.dump(data, f, ensure_ascii=False)

def get_jwe_token(user):
    log("========================== Getting JWE Token ==========================",'green')    

    req_headers = {
        "signature" : user['signature'],
        "certificate" : user['certificate'],
        "nonce" : user['nonce']
    }
    req_body = {}
    url = "https://chaser-ap03-apnortheast2.samsungiotcloud.com/accesstoken"
    response = requests.post(url, headers=req_headers, json=req_body)

    print("Here're your request headers (sensitive info is blurred out ***): ")
    print("URL: ", url)
    req_headers["signature"] = req_headers["signature"][:4] + "***"
    req_headers["certificate"] = req_headers["certificate"][:4] + "***"
    req_headers["nonce"] = req_headers["nonce"][:4] + "***"
    print(req_headers)

    if not response.status_code == 200:
        log("error getting jwe token", 'red')
        exit()
    jwe_token = response.json()["accessToken"]
    print("Here's the JWE token: {}".format(jwe_token[:6]+"***"))
    return jwe_token

# gets a new signin token (userauth_token)
def request_authentication(user):
    password = user['password']
    login_id = user['login_id']
    signin_client_secret = user['signin_client_secret']

    log("========================== Getting Signin Token ==========================",'green')    
    req_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }


    req_body = {
            'signin_client_id': signin_client_id,
            'check_2factor_authentication' : 'Y',
            'originalAppID' : client_id,
            'devicePhysicalAddressText' : 'IMEI%3AAAAAAAAAAAAAAAA',
            'customerCode' : 'NEE',
            'deviceMultiUserID':'0',
            'phoneNumberText':'',
            'deviceName':'hero2lte',
            'client_id':client_id,
            'deviceTypeCode':'PHONE+DEVICE',
            'password' : password,
            'deviceUniqueID' :  physical_address_text,
            'scope':'iot.client+mcs.client+galaxystore.openapi',
            'serviceRequired':'N',
            'physical_address_text':physical_address_text,
            'login_id_type':'email_id',
            'mobileCountryCode':'505',
            'mobileNetworkCode' : '00',
            'deviceNetworkAddressText':'02%3A00%3A00%3A00%3A00%3A00',
            'signin_client_secret':signin_client_secret,
            'service_type' : 'M',
            'isRegisterDevice':'Y',
            'deviceModelID':'SM-G935F',
            'deviceSerialNumberText': 'AAAAAAAAAAA',
            'softwareVersion':'R16NW%2FG935FXXU8ETI2',
            'username':login_id
    }
    req_body_str = "&".join("%s=%s" % (k,v) for k,v in req_body.items())
    url = "https://us-auth2.samsungosp.com/auth/oauth2/requestAuthentication"
    response = requests.post(url, headers=req_headers, data=req_body_str)
    print("Here's your request (sensitive info is blurred out ***): ")
    print("URL: ", url)
    req_body["signin_client_id"] = "*" * 10
    req_body["client_id"] = "*" * len(req_body["client_id"])
    req_body["password"] = "*" * len(req_body["password"])
    req_body["deviceUniqueID"] = "*" * len(req_body["deviceUniqueID"])
    req_body["physical_address_text"] = "*" * len(req_body["physical_address_text"])
    req_body["deviceNetworkAddressText"] = "*" * len(req_body["deviceNetworkAddressText"])
    req_body["signin_client_secret"] = "*" * len(req_body["signin_client_secret"])
    req_body["username"] = "*" * len(req_body["username"])
    pprint.pprint(req_body)

    if response.status_code == 200:
        userauth_token = response.json()["userauth_token"]
        return userauth_token
    else:
        log("failed to get the userauth_token",'red')
        print(response.json())
        exit()


# get a new Bearer token to access web services if the current one expired
def get_token(user):
    userauth_token = user['userauth_token']
    login_id =  user['login_id']

    log("========================== Getting Bearer Token ==========================",'green')    
    req_headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }
    req_body = {
        'check_email_validation' : 'Y',
        'authenticate' : 'Y',
        'data_collection_accepted':'N',
        'client_id': client_id,
        'lang_code':'EN',
        'appId': client_id,
        'scope':'iot.client+mcs.client+galaxystore.openapi',
        'login_id': login_id,
        'package':'com.samsung.android.oneconnect',
        'login_id_type':'email_id',
        'physical_address_text':physical_address_text,
        'userauth_token': userauth_token
    }
    req_body_str = "&".join("%s=%s" % (k,v) for k,v in req_body.items())
    url = 'https://us-auth2.samsungosp.com/auth/oauth2/authWithTncMandatory'
    response = requests.post(url, headers=req_headers, data=req_body_str)

    print("Here's your request (sensitive info is blurred out ***): ")
    print("URL: ", url)
    req_body["client_id"] = "*" * len(req_body["client_id"])
    req_body["login_id"] = "*" * len(req_body["login_id"])
    req_body["physical_address_text"] = "*" * len(req_body["physical_address_text"])
    req_body["userauth_token"] = "*" * len(req_body["userauth_token"])
    pprint.pprint(req_body)

    if response.status_code == 200:
        token = response.json()["token"]["access_token"]
        return token
    else:
        log("Signin token expired? Get a new userauth_token",'red')
        print(response.json())
        exit()


def main():
    global bearer_token, shared_secret, jwe_token, fake_identity_addr, location_id, room_id, requester, user_idx, fmm_app_id, device_name, physical_address_text, client_id, signin_client_id
    print("Please manually configure the user information in user_info.json, then remove this")
    exit()
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', dest='user_idx', type=int, default=1, help='--user 0 or 1')
    parser.add_argument('-userauth', action='store_true')
    parser.add_argument('-bearer', action='store_true')
    parser.add_argument('-jwe', action='store_true')

    args = parser.parse_args()
    user_idx = args.user_idx
    user = load_user_info(user_idx)
    bearer_token = user['bearer_token']
    jwe_token = user['jwe_token']
    requester = user['requester']
    physical_address_text =  user['physical_address_text']
    signin_client_id =  user['signin_client_id']
    client_id =  user['client_id']

    if args.userauth:
            auth_token = request_authentication(user)
            user['userauth_token'] = auth_token
            save_user_info(user,user_idx)

    if args.bearer:
        bearer_token = get_token(user)
        user['bearer_token'] = bearer_token
        save_user_info(user,user_idx)

    if args.jwe:
        jwe_token = get_jwe_token(user)
        user['jwe_token'] = jwe_token
        save_user_info(user,user_idx)

if __name__ == '__main__':
    main()