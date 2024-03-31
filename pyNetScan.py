#!/usr/bin/env python
import nmap
import requests
import time
import sys
import os.path

fileHandle = ""
macEntriesFilePath = 'mac_names.txt'
separator = ';'

def macFileAppendLine(string: str):
    fileHandle = open(macEntriesFilePath,"a")
    fileHandle.write(string + '\n')
    fileHandle.close() 

# Create file if it does not exist
if os.path.isfile(macEntriesFilePath) is False:
    fileHandle = open(macEntriesFilePath, 'a')
    fileHandle.close()

# Parameter check
if len(sys.argv) != 4:
    print("Parameter error")
    sys.exit(-1)

scanNet = sys.argv[1]
if scanNet.count('.') != 3 or scanNet.count('/') != 1:
    print("Parameter 'net' error")
    sys.exit(-1)

if sys.argv[2] == 'True':
    macVendorLookup = True
elif sys.argv[2] == 'False':
    macVendorLookup = False
else:    
    print("Parameter 'lookupMmode' error")
    sys.exit(-1)

if os.path.isfile(sys.argv[3]):
    macEntriesFilePath = sys.argv[3]
else:
    print("File for local MAC lookup doesn't exist")
    sys.exit(-1)

colWidthIP = 15
colWidthDesc = 50

# Load file entries for matching device names
existing_entries = {}
try:
    with open(macEntriesFilePath, 'r') as file:
        for line in file:
            if separator in line:
                mac, name = line.strip().split(separator)
                existing_entries[mac] = name
except FileNotFoundError:
    print("File not found")
    pass

# Create nmap instance
nm = nmap.PortScanner()

print("")
print("Starting scan on net " + scanNet + "...")
print("")

# Initiate scan
a = nm.scan(hosts=scanNet, arguments='-sP')

# Show scan result with name if it exists
for k, v in a['scan'].items():
    if str(v['status']['state']) == 'up':
        try:
            ip_address = str(v['addresses']['ipv4'])
            mac_address = str(v['addresses']['mac'])
            name = existing_entries.get(mac_address)  # Use the device name if it exists
            ipLen = len(ip_address)
            macLen = len(mac_address)
            strIP = ip_address.ljust(colWidthIP)
            strMAC = mac_address.ljust(20)
            strUnknown = "Unknown".ljust(colWidthDesc)
            strName = ""
            if name != None:
                nameLen = len(name)
                strName = name.ljust(colWidthDesc)
                print(f"{strIP} => {strName} {strMAC}")
            else:
                if macVendorLookup:
                    manufacturer = requests.get(f"https://api.macvendors.com/{mac_address}").text
                    if 'Not Found' not in manufacturer:
                        print(f"{strIP} => {strUnknown} {strMAC} {manufacturer}")
                        macFileAppendLine(mac_address + separator + "Unknown (" + manufacturer + ")")
                    else:
                        print(f"{strIP} => {strUnknown} {strMAC} Vendor not found")
                    time.sleep(0.5)   # Slow down access to avoid error messages in free mode
                else:
                    print(f"{strIP} => {strUnknown} {strMAC}")
                    macFileAppendLine(mac_address + separator + "Unknown")

        except KeyError:
            ip_address = str(v['addresses']['ipv4'])
            strIP = ip_address.ljust(colWidthIP)
            if 'localhost' in v['status']['reason']:
                strName = "Localhost"
                print(f"{strIP} => {strName} ")
            else:
                print(f"{strIP} => Unknown Error ")

print("")
print("Scan finished")
print("")

