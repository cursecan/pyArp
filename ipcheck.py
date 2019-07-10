from scapy import all as scapy
import argparse


def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument('-t', '--target', dest='target', help='Target IP/IP range')
    options = parse.parse_args()
    return options


def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast = broadcast/arp_req

    asnwer_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for i in asnwer_list:
        clien_dict = {
            'ip': i[1].psrc,
            'mac': i[1].hwsrc
        }

        client_list.append(clien_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS")
    print("-------------------------------------------------")
    for i in result_list:
        print("{}\t\t{}".format(i['ip'], i['mac']))


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)