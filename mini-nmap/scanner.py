from scapy.all import IP, TCP, sr1, sr
from colorama import Fore, Style, init
import socket

init(autoreset=True)

class MiniNmap:
    def init(self):
        self.open_ports = []

    def get_host_ip(self, target):
        try:
            return socket.gethostbyname(target)
        except:
            print(f"{Fore.RED}[-] Could not resolve {target}")
            return None

    def ping_sweep(self, target):
        print(f"{Fore.CYAN}[+] Pinging {target}...")
        ans, _ = sr(IP(dst=target)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
        if ans:
            print(f"{Fore.GREEN}[+] {target} is UP")
            return True
        else:
            print(f"{Fore.RED}[-] {target} is DOWN")
            return False

    def port_scan(self, target, ports=[22, 80, 443, 8080]):
        print(f"{Fore.CYAN}[+] Scanning ports on {target}...")
        for port in ports:
            pkt = IP(dst=target)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=1, verbose=0)
            
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:
                    print(f"{Fore.GREEN}[+] Port {port} is OPEN")
                    self.open_ports.append(port)
                elif resp[TCP].flags == 0x14:
                    print(f"{Fore.YELLOW}[\~] Port {port} is CLOSED")
        return self.open_ports