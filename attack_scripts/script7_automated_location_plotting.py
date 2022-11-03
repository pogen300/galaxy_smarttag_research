# -----------------------------------------------------------
# This script automates the location pulling process of a registered tag you own,
# and plots the locations and the estimated path the tag has travelled during
# the user specified duration based on the location data returned by the server
# this is how each location report in the server's response look like:
# {'latitude': '...', 'longitude': '...', 'accuracy': '...', 'lastUpdateTime': ...}
# (c) 2022 Tingfeng Yu
# -----------------------------------------------------------

import argparse
import time
from datetime import datetime

import pytz
import requests
from gmplot import gmplot
from script5_get_tokens import *
from utils import log

# some globals, need to be reconfigured to fetch locations associated with a different device/account

# Bearer token
bearer_token = None

# can be found in the finalization response output file
device_id = None

# tied with the experiment account
requester = None

fmm_app_id = None

# pull locations from the last 24h (max 200)
def get_locations(days):
    global bearer_token, device_id, requester, fmm_app_id
    cur_time = time.time()
    start_time = cur_time - (days * 86400)  # 86400 seconds per day
    cur_time = int(cur_time * 1000)
    start_time = int(start_time * 1000)
    url = "https://api.smartthings.com/installedapps/{}/execute".format(fmm_app_id)
    req_body = {
        "parameters": {
            "requester": requester,
            "clientType": "aPlugin",
            "extraUri": "/trackers/{}/geolocations?order=asc&startTime={}&endTime={}&isSummary=true&limit=200".format(
                device_id, start_time, cur_time
            ),
            "method": "GET",
            "requesterToken": bearer_token,
            "encodedBody": "",
            "clientVersion": "1",
            "uri": "/trackerapi",
        }
    }
    print(req_body)
    req_headers = {"Authorization": "Bearer " + bearer_token}
    geolocations = []
    location_history = [[], [], []]
    response = requests.post(url, headers=req_headers, json=req_body)
    if response.status_code == 200:
        print(response.json())
        if response.json()["statusCode"] == 200:
            geolocations = response.json()["message"]["geolocations"]
        else:
            log("failed to get locations", "red")
            exit()
    else:
        log("failed to get locations", "red")
        print(response.status_code, response)
        exit()
    if len(geolocations) == 0:
        log("no geolocations, exitting...", "blue")
        exit()
    for item in geolocations:
        try:
            location_history[0].append(float(item["latitude"]))
            location_history[1].append(float(item["longitude"]))
            location_history[2].append(item["lastUpdateTime"])
        except:
            log("failed to add location data", "red")
            exit()
    return location_history


# plot locations on map
def plot_locations(location_history, zoom_level):
    tz = pytz.timezone("Australia/Sydney")
    lats = location_history[0]
    lons = location_history[1]
    times = location_history[2]
    gmap = gmplot.GoogleMapPlotter(lats[0], lons[0], zoom_level)

    for i in range(0, len(lats)):
        dt = datetime.fromtimestamp(times[i] // 1000, tz=tz)
        dt = dt.strftime("%Y-%m-%d-%H-%M-%S")
        my_label = str(i) + ": " + dt
        gmap.marker(lats[i], lons[i], label=my_label)

    gmap.plot(lats, lons, "cornflowerblue", edge_width=5)
    gmap.draw("location_history.html")


def main():
    global bearer_token, fmm_app_id, requester, device_id
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--user", dest="user_idx", type=int, default=0, help="--user 0 or 1"
    )
    args = parser.parse_args()
    user_idx = args.user_idx

    user = load_user_info(user_idx)
    bearer_token = user["bearer_token"]
    fmm_app_id = user["fmm_app_id"]
    requester = user["requester"]
    device_id = user["device_id"][0]
    # device_id = "4774f3d4-3da6-4513-8cec-1c16dae071b9"

    # configure this to True to get a new bearer token if it expires
    no_valid_bearer_token = False
    no_valid_userauth_token = False
    if no_valid_userauth_token:
        auth_token = request_authentication(user)
        user["userauth_token"] = auth_token
        save_user_info(user, user_idx)
    if no_valid_bearer_token:
        bearer_token = get_token(user)
        user["bearer_token"] = bearer_token
        save_user_info(user, user_idx)
    days = 1  # get locations from the last days * 24 h
    zoom_level = 13
    location_history = get_locations(days)
    plot_locations(location_history, zoom_level)


if __name__ == "__main__":
    main()
