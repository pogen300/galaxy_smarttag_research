#!/bin/bash

systemctl restart bluetooth
hciconfig hci0 up
btmgmt power off
btmgmt le on
btmgmt bredr off
#btmgmt ssp on
#btmgmt privacy on
btmgmt connectable on
btmgmt discov on
btmgmt pairable on
btmgmt power on

