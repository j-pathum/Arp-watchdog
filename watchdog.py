from scapy.all import sniff, ARP
import sys

# A dictionary to store known IP-MAC pairings
# Format: { '192.168.1.1': 'AA:BB:CC:DD:EE:FF' }
ip_mac_table = {}

def process_packet(packet):
    # We only care about ARP packets (Protocol that maps IP to MAC)
    if packet.haslayer(ARP):
        
        # op=2 means it is an ARP "Reply" (Response)
        # Someone is saying "Hi, this IP belongs to this MAC address"
        if packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            try:
                # Check if we have seen this IP before
                old_mac = ip_mac_table[src_ip]

                # LOGIC: If the IP is the same, but the MAC is different,
                # someone is lying!
                if old_mac != src_mac:
                    print(f"\n[!!!] ALERT: MITM ATTACK DETECTED [!!!]")
                    print(f"The IP {src_ip} moved from MAC {old_mac} to {src_mac}")
                    print("Someone is spoofing this address!\n")
            
            except KeyError:
                # If we haven't seen this IP before, simply memorize it
                ip_mac_table[src_ip] = src_mac
                print(f"[+] Learned: {src_ip} is at {src_mac}")

def main():
    print("--- ARP Watchdog Active (Requires Root/Sudo) ---")
    print("Listening for ARP Spoofing attempts...")
    
    # store=False prevents Scapy from eating up all your RAM
    sniff(store=False, prn=process_packet)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping Watchdog.")
    except PermissionError:
        print("Error: Run this with sudo (Linux/Mac) or Administrator (Windows).")
