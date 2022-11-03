# galaxy_smarttag_research
The artefact repository for my honors research project (COMP4550) on the Galaxy SmartTag

## Note
For privacy concern, files containing personal data, e.g., samsung account related info, have been excluded. Also, sensitive data contained in some scripts (will be explained in the associated sections) has been removed and you will have to manually configure them with your own user info/SmartTag related info to reproduce any attacks. 

If you have trouble setting up the script, or want to request for more information. Please let me know.

## repo structure
    .
    ├── attack_scripts
    │   └── locations
    ├── dfu_mitigation
    │   ├── ble_app_buttonless_dfu_aes
    │   └── bootloader
    ├── investigation
    │   ├── ble_passive_scanning
    │   ├── log_analysis
    │   │   ├── owner_tag_interaction
    │   │   │   └── firmware_update
    │   │   ├── registration_ble
    │   │   ├── silent_pairing_owner
    │   │   └── silent_pairing_tag
    │   ├── reverse_engineering
    │   │   ├── firmware
    │   │   ├── fmm
    │   │   │   └── native_library_analysis
    │   │   └── smarthings
    │   └── web_traffic_analysis
    │       ├── command_set
    │       ├── location_querying
    │       ├── location_report
    │       │   ├── 1_nonce
    │       │   ├── 2_access_token
    │       │   ├── 3_location_report_helper
    │       │   └── 4_location_report_owner
    │       └── registration
    │           ├── 1_shared_secret
    │           ├── 2_ownership_status
    │           └── 3_finalization
    └── other_scripts




### ``investigation`` folder
This folder contains data relevant to the investigation process for SmartTag's OF protocol.

Its sub-folders are organized based on the investigation approaches, which corresponds to the methodology chapter of my thesis.

#### ``ble_passive_scanning``
This folder has multiple CSV files containing BLE data collected from BLE passive scanning over days. The patterns observed in the collected data were used to help understand the underlying behavior of a tag.

#### ``log_analysis``
This folder contains the log data (logcat output or Bluetooth HCI snoop log) produced during various operations, e.g., tag registration, command exchange, silent pairing attacks. For more details, see ``notes.md`` in the folder.

**Note** some logcat files have been removed, as the files are huge and may contain sensitive user data related to my Samsung account

#### ``reverse_engineering``
This folder contains data related to my reverse engineering approaches. The subfolders are organized based on the reverse-engineered target:

+ ``firmware``: the smarttag's firmware reverse-engineered using Ghidra. I have not tested whether this gzf (Ghidra Zip File) file (containing the exported program) can be imported successfully. If you have trouble importting it/seeing the refactored functions/comments, pls let me know.
+ ``fmm``: 
  + I reverse-engineered different versions of the FMM apk file. To inspect a refactored apk file, run ``jadx-gui`` command in the same directory and open the ``fmm.apk.jadx`` file.
  + The **native_library_analysis*** subfolder contains my analysis of a native library used by FMM apk. 
    + As mentioned in thesis, the JWE token renewal process involves loading certificates and a private key from a keystore file. The loading process involves using a native library ``libfmm_ct.so``. Since the native library is obfuscated, I used a dynamic analysis approach to observe its behavior at runtime.
    + To this end, I created a fake fmm apk (the ``FMM`` subfolder), with the same package name and created the function to interface with native library methods and inspect their output. The ``FMM`` subfolder can be opened as an Android Studio Project and run on an Android emulator. The output of the native library methods will be dumped as a part of the debug log messages.
+ ``smartthings``: the smartthings apk was thoroughly reverse-engineered using JADX-GUI. To inspect the refactored file, un ``jadx-gui`` command in the same directory and open the ``base.apk.jadx`` file.

#### ``web_traffic_analysis``
This folder contains HTTPS requests/responses captured by BurpSuite during different server communication process, e.g., registraion, location reporting.

+ ``command_set``: The request and response for obtaining the specification of the command service (uuid fd5a) characteristics.
+ ``location_querying``: The request and response for an owner device to pull location updates of a lost tag from the server
+ ``location_report``: The request and response for online devices to report geolocations of tags
+ ``registration``: The requests and responses occurred at the tag registration process. 

**Note** some sensitive data, such as serial number and user id are partially blurred out.


### ``attack_scripts`` folder
This folder contains the main "attack" scripts related to the security and privacy analysis process. For details, see the ``HOWTO.md`` file inside this folder.

### ``other_scripts``
This folder contains some other scripts relevant to the security and privacy analysis:

+ ``check_irk.py``: this script resolves RPAs of a paired device using the IRK exhcnaged at the pairing process. It was used to analyze the silent pairing attacks for SmartTags and Owner Device and comfirm that the attacks can be used for identity tracing.
+ ``command_replay.py``: this script was used to confirm the command replay attack. The script uses the "playsound" command as an example.
+ ``parse_tag_ble.py``: this script is a Python version of the reverse-engineered BLE parsing function found in the ``smartthings.apk``. For details of the reverse-engineering findings, see Appendix 2 in my thesis.

### ``dfu_mitigation`` folder
This folder is related to my proposed mitigation for the DFU service vulnerability. It contains a modified version of the bootloader module and an DFU example application from nRF SDK 17.1.0. 

The modification essentially uses the nRF crypto module to secure the DFU service with an AES cipher. 

To inspect the modification, you will need to download the nRF SDK 17.1.0 from the official website (<https://www.nordicsemi.com/Products/Development-software/nrf5-sdk/download>), then
+ replace ``nRF5_SDK_17.1.0/components/libraries/bootloader`` with the modified ``bootloader`` folder
+ add the ``ble_app_buttonless_dfu_aes`` folder to ``nRF5_SDK_17.1.0/examples/ble_peripheral``

The DFU AES application can be opened in SEGGER embedded studio. To flash and test the application, You will need to have an nRF DK (the one I used was nRF52832).