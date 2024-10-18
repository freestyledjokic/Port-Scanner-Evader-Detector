################################################################################
#
#                               PSDetect.py
#       HW2: Port Scanner Detector
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 04/24/2024
#       Program purpose: Detects potential port scanners by monitoring incoming
#                        packets and recording suspicious scanning behavior in 
#                        "detector.txt"
#
#
################################################################################

import sys,signal,time
from scapy.all import sniff, IP, TCP


# Dictionary to track connection attempts
scanning_attempts = {}
# Set that tracks IPs that have already been detected as scanners
detected_scanners = set()

"""
signal_handler(sig, frame)

Purpose:
        Handles signals received by the program, specifically the SIGINT signal,
        which is typically sent by pressing Ctrl+C

Parameters:
        The signal number (integer). The current execution frame (frame object)

Return:
        None
"""
def signal_handler(sig, frame):
        sys.exit(0)

"""
sort_ports(recent_entries)

Purpose:
        Sorts the list of recent entries containing port numbers and removes 
        duplicates

Parameters:
        recent_entries: A list of tuples representing recent entries. Each tuple
                        should contain a port number as its first element

Return:
        sorted_unique_ports: A list of unique port numbers sorted in ascending 
                             order
"""
def sort_ports(recent_entries):
        sorted_ports = []

        # Loop through each entry in the recent_entries list
        for entry in recent_entries:
                port = entry[0]
                sorted_ports.append(port)

        # Remove duplicate ports by converting the list to a set
        unique_ports = set(sorted_ports)

        # Sort the unique ports and convert them back to a list
        sorted_unique_ports = sorted(unique_ports)

        return sorted_unique_ports

"""
has_consecutive_ports(sorted_ports)

Purpose:
        Checks if the given list of sorted port numbers contains 15 
        consecutive ports

Parameters:
        sorted_ports: A list of sorted port numbers

Return:
        True if the list contains 15 consecutive ports, False otherwise
"""
def has_consecutive_ports(sorted_ports):
        for i in range(len(sorted_ports) - 14):
                if sorted_ports[i + 14] - sorted_ports[i] == 14:
                        return True
        return False

"""
detect_scan(packet)

Purpose:
        Handles incoming packets and checks for suspicious scanning behavior.
        It tracks the number of scanning attempts from each source IP within the
        last five minutes. If an IP has scanned more than 15 consecutive ports
        in the last five minutes, it is considered a potential scanner and is 
        recorded in a file named "detector.txt"

Parameters:
        packet: The packet received by the program.

Return:
        None
"""
def detect_scan(packet):
        if IP in packet and TCP in packet:
                # Get the source IP and port number
                source_ip = packet[IP].src
                port = packet[TCP].dport
                current_time = time.time()

                # Initialize the list for the source IP if it does not exist
                if source_ip not in scanning_attempts:
                        scanning_attempts[source_ip] = []

                # Record the timestamp for each packet received
                scanning_attempts[source_ip].append((port, current_time))

                # Keep only the entries made in the last five minutes
                recent_entries = []
                for entry in scanning_attempts[source_ip]:
                        if current_time - entry[1] <= 300:
                                recent_entries.append(entry)
                scanning_attempts[source_ip] = recent_entries

                # Check if this IP has scanned more than 15 consecutive ports
                # in the last 5 minutes
                if len(recent_entries) >= 15:
                        sorted_ports = sort_ports(recent_entries)
                        if has_consecutive_ports(sorted_ports):
                                if source_ip not in detected_scanners:
                                        detected_scanners.add(source_ip)
                                        # Record the scanner IP to a file
                                        file = open("detector.txt", "a")
                                        file.write(f"Scanner detected. The scanner originated from host {source_ip}\n")
                                        # Close the file
                                        file.close()

                                # Clear the list for this IP to prevent repeated detections
                                scanning_attempts[source_ip] = []

"""
main()

Purpose:
        Initiates the port scanner detection process by starting a packet 
        sniffing session on the 'lo' (loopback) interface. Specifies the 
        detect_scan function to be called for each packet received. The 
        sniffing process does not store packets in memory (store=0)

Parameters:
        None

Return:
        None
"""
def main():
        sniff(iface='lo', prn=detect_scan, store=0)
       

if __name__ == "__main__":
        signal.signal(signal.SIGINT, signal_handler)
        main()