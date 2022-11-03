# How To

## Dependencies
packages required to install Dbus-Python

``
sudo apt-get install libdbus-glib-1-dev libdbus-1-dev
``

packages required to install gi

``
sudo apt install libcairo2-dev libgirepository1.0-dev gir1.2-gtk-3.0
``


then install dependencies in requirements.txt

``
pip3 install --no-use-pep517  -r requirements.txt
``

If not working, let me know...

## Script info

+ ``script0_registration_attacks.py``, ``script2_registered_tag.py``, and ``script5_get_tokens.py`` are used to form the registration flow attacks. The details will be elaborated in the next section. 
+ ``script1_new_tag.py`` impersonates a non-registered SmartTag that can be detected by the SmartThings app on a Galaxy device. To register the impersonated tag, one will need to set up a proxy server to intercept the shared secret returned by the SmartThings Server and manually send it to the impersonation script (enter the value in the terminal window when the script asks for a shared secret)
+ ``script3_nonce_reflection.py`` used to confirm the nonce reflection attack.
+ ``script4_silent_pairing.py`` used to confirm the silent pairing attack (with an Owner Device)
+ ``script7_automated_location_plotting.py`` used to automate the location querying process then plot the pulled location data and the estimated path on a Google map. For some plotted examples, see the html files in the ``locations`` subfolder.
+ ``script8_fake_location_report.py`` used to confirm the fake location report vulnerabilty

## About the registration attack scripts
To run the attack scripts, you will need to manually configure the **attack_scripts/user_info.json**. 

The default file content:

    {
        "users":[
        {
            "userauth_token":"DEFAULT",
            "login_id":"TODO",
            "password":"TODO",
            "signature":"TODO",
            "certificate":"TODO",
            "nonce":"TODO",
            "signin_client_secret":"TODO",
            "location_id":"TODO",
            "room_id":"TODO",
            "device_id":[],
            "requester":"TODO",
            "bearer_token":"DEFAULT",
            "jwe_token":"DEFAULT",
            "fmm_app_id":"TODO",
            "physical_address_text":"TODO",
            "signin_client_id":"TODO",
            "client_id":"TODO"
        }
        ]
    }

You can leave the "DEFAULT" values and run **script5** to update them, but you will need to replace the "TODO"s to valid user info. To obtain each value, you can follow these steps: 
+ set up the BurpSuite proxy to monitor the data exchange between a rooted phone and remote servers (a Galaxy S7 Edge phone was used for my experiments):
+ log in SmartThings using a Samsung account (remember to set "turn off do 2-factor authentication on this device" when logging in).
+ Then register a legit SmartTag through normal flow (Devices -> add device)
+ After registration complete, go to SmartThings Find and browse the locaiton history of the registered tag (Life -> Find)

After completing the above steps, go to the "HTTP history" tab in BurpSuite, you should be able to observe:

### Login request
A POST request to https://us-auth2.samsungosp.com/auth/oauth2/requestAuthentication containing the **signin_client_id**, **client_id**, **password**, **physical_address_text**, **signin_client_secret**, and **login_id** 

### Registration request
A POST request to https://client.smartthings.com/miniature/mobile containing the **location_id** and **room_id**

### Location reporting request
A POST request to https://chaser-....samsungiotcloud.com/accesstoken containing the **signature**, **certificate**, and **nonce**

### Location pulling request
Multiple POST requests to https://api.smartthings.com/installedapps/.../execute For example:
+ ***req 1***: https://api.smartthings.com/installedapps/8a30fbe2.../execute
+ ***req 2***: https://api.smartthings.com/installedapps/7d4a67c0.../execute
+ ...

These requests can be differentiated based on their request body. Say the body of ***req 2*** looks like:

    {"parameters":{"requester":"cfs9l1j2jx","clientType":"aPlugin","extraUri":"/trackers/.../geolocations?order=asc&startTime=1665320400001&endTime=1665406799999&isSummary=true&limit=50","method":"GET","requesterToken":"AUI71AGQpJ3jDRzSPJSfaNhvC","encodedBody":"","clientVersion":"1","uri":"/trackerapi"}}

Then you know it corresponds to a request for the FMM web plugin. In this example, the **fmm_app_id** would be 8a30fbe2-..., the **requester** would be "cfs9l1j2jx".


+ run the $setup.sh$ before running any script that involves BLE stuffs...
  + ``sudo ./setup.sh`` 

### User information ``user_info.json``
During testing, I stored the information of my experiment accounts in **attack_scripts/user_info.json**, but I have removed them for privacy concerns. For the ease of reproducing the attacks, the information of my test accounts can be made available upon request.

## Scripts Info
### Impersonation script
**script2** can be used to set up a registered SmartTag that performs OF operation and GATT interactions with its owner device:
+ broadcasts OF data with payload that updates every 15 minutes
+ accept BLE authentication requests from the owner and perform the two-way authentication process
+ output any data received from the owner device to the terminal.
+ the script will also attempt to trigger the remote ringing command on the owner device upon authentication

The following scripts are used by **script2**:

+ **smarttag_crypto.py**: crypto algorithms for tag impersonation
implements some reverse-engineered crypto algorithms for smarttags
  + decrypt/encrypt GATT commands
  + decrypt/encrypt nonces
  + generate privacy ID pool
  + generate signature
  + generate BLE adv
+ **smarttag\_gatt\_server.py**: GATT server for tag impersonation
  + sets up a GATT server that has the same architecture and content as a legitimate SmartTag


To run **script2**: ``python3 script2*.py`` (you need to configure the privacyID, privacyIV, and mastersecret values in **main()** manually. These values should be saved to the **fianalization_response.json** file after registering a tag through either attack)


### Get access tokens
**script5** fetches necessary tokens to interact with the SmartThings server and the Location server. You might need to run this before performing each attack in case old access tokens have expired.

To run this script: ``python3 script5*.py --user i -userauth -bearer -jwe``
+ $i$ specifies the $i$th user in the **user_info.json**. $i=0$ when there is only one user 
+ use the 3 optional flags to specify the token(s) you want to update
 
### Registration attacks
**script0** automates the 2 attacks discussed in the report. 

To run attack 1: ``python3 script0*.py --user i --attack 1 --sn FDAB...``
+ the value for $sn$ should correspond to the identifier of a non-registered tag
To run attack 2: ``python3 script0*.py --user i --attack 2 --sn FDAB... --fake-sn ...``
+ the value for $fake-sn$ should differ from $sn$, corresponds to an invalid identifier that does not conflict with the identifier of any registered device
