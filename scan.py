import scapy.all as scapy
import optparse
from time import sleep
import sys

def get_ip_range():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--ip-range", dest="ip", help="IP Range to check how many hosts are live")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify range of ip, type --help for more info")
    else:
        return options

def scan_clients(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    request_recieved_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for elements in request_recieved_list:
        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    words = "[+] Scanning IP's in the Network..."
    for char in words:
        sys.stdout.write(char)
    characters = "\n[+] Scan Complete"
    for chars in characters:
        sleep(0.2)
        sys.stdout.write(chars)
    word = "\n[+] Showing results..."
    for chars in word:
        sleep(0.2)
        sys.stdout.write(chars)
    print("\n-------------------------------------------")
    print("IP\t\t\tMAC ADDRESS\n-------------------------------------------")
    for clients in result_list:
        print(clients["ip"] + "\t\t" + clients["mac"])
    print("-------------------------------------------")

options = get_ip_range()
client_scan_result = scan_clients(options.ip)
print_result(client_scan_result)
