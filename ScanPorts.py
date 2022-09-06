#!/usr/bin/python3
from ast import arguments
from itertools import count
from unittest import result
import nmap
print()
print(" _  _ ___   ___              _ _       ")
print("| || |__ \ / _ \            (_) |      ")
print("| || |_ ) | | | | __ ___   ___| | __ _ ")
print("|__   _/ /| | | |/ _` \ \ / / | |/ _` |")
print("   | |/ /_| |_| | (_| |\ V /| | | (_| |")
print("   |_|____|\___/ \__,_| \_/ |_|_|\__,_|")
print()
print() 
print("+---------------------------------------------------------------------------+")
print("| [Info] Herramienta para escanear los puertos abiertos en una dirección IP |")
print("| * Escrito en Python y utiliza Nmap                                     |")
print("+---------------------------------------------------------------------------+ ")
print() 
host= input ("[+] Introduce la Ip Objetivo: ")
nm= nmap.PortScanner()
puertos_abiertos= "-p"
count=0
results= nm.scan(host, arguments="-p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts ")
#result = nm.scan(host)
#print (result)
print("Host : %s (%s" % host)
print("State : %s" % nm[host].state())
for proto in nm[host].all_protocols():
    print("Protocol : %s" % proto)
    lport = nm[host][proto].keys()
    sorted(lport)
    for port in lport:
        print ("port : %s\tstate : %s" % (port, nm[host][proto][port]["state"]))
        if count==0:
            puertos_abiertos= puertos_abiertos+" "+str(port)
            count=1
        else:
            puertos_abiertos= puertos_abiertos+","+str(host)

print("Puertos abiertos: "+puertos_abiertos+" "+ str(host))


