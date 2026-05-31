from scapy.all import ARP, Ether, srp
import argparse
import socket
import time
from datetime import datetime

# Try to import tabulate for nice tables (fallback if not installed)
try:
    from tabulate import tabulate
    USE_TABULATE = True
except ImportError:
    USE_TABULATE = False

def get_vendor(mac):
    """Simple vendor lookup"""
    vendors = {
        '00:11:22': 'Test Vendor',
        'AC:BC:32': 'TP-Link',
        '00:1A:2B': 'Dell',
        '3C:06:30': 'Samsung',
        'F0:98:9C': 'Apple',
        # Add more as needed
    }
    prefix = mac.upper()[:8]
    return vendors.get(prefix, 'Unknown')

def scan_network(target):
    print(f"\n🔍 Scanning {target} ...")
    print("=" * 60)
    
    # Create ARP request
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    start_time = time.time()
    
    try:
        result = srp(packet, timeout=3, verbose=0)[0]
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        print("Tip: Try running as Administrator on Windows.")
        return
    
    devices = []
    
    for sent, received in result:
        device = {
            'IP': received.psrc,
            'MAC': received.hwsrc,
            'Vendor': get_vendor(received.hwsrc)
        }
        devices.append(device)
    
    # Sort by IP
    devices.sort(key=lambda x: socket.inet_aton(x['IP']))
    
    scan_time = time.time() - start_time
    
    # Display results
    if devices:
        print(f" Scan completed in {scan_time:.2f} seconds")
        print(f" {len(devices)} device(s) found on the network\n")
        
        if USE_TABULATE:
            table = [[d['IP'], d['MAC'], d['Vendor']] for d in devices]
            print(tabulate(table, headers=["IP Address", "MAC Address", "Vendor"], tablefmt="grid"))
        else:
            print(f"{'IP Address':<18} {'MAC Address':<20} Vendor")
            print("-" * 60)
            for d in devices:
                print(f"{d['IP']:<18} {d['MAC']:<20} {d['Vendor']}")
    else:
        print(" No devices found. Try a different target or network.")

def main():
    parser = argparse.ArgumentParser(description="Mini Nmap - Simple Network Scanner")
    parser.add_argument("target", nargs="?", help="Target IP / Range (e.g. 192.168.1.1/24)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds")
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print(" Mini Nmap - Network Scanner".center(60))
    print("="*60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    if args.target:
        scan_network(args.target)
    else:
        target = input("Enter target IP or hostname (e.g. 192.168.1.1/24): ").strip()
        if target:
            scan_network(target)
        else:
            print(" No target provided.")

if __name__ == "__main__":
    main()