#!/bin/bash

# Specify the folder containing pcap files
pcap_folder="pcap_files"

# Iterate through pcap files in the folder
for pcap_file in "$pcap_folder"/*; do
    printf "$pcap_file:\n"
    # Check if there are pcap files in the folder
    if [ -e "$pcap_file" ]; then
        ./dhcp-stats -r "$pcap_file" "192.168.1.0/24" "192.168.0.0/22" "172.16.32.0/24"
    else
        echo "No pcap files found in $pcap_folder."
        exit 1
    fi
    printf "\n"
done
