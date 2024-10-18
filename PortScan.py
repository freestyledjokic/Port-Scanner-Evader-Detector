################################################################################
#
#                               PortScan.py
#       HW2: Port Scanner
#       Author: Andrej Djokic
#       UTLN: adjoki01
#       Date 04/21/2024
#       Program purpose: A TCP port scanning tool to detect open ports on a 
#                        target machine and record results in "scanner.txt"
#
#
################################################################################

import socket,argparse,time

"""
parse_arguments()

Purpose:
        Parses command-line arguments to extract the target hostname or IP 
        address for the TCP port scanning process

Parameters: 
        None
        
Return:
        args: An argparse.Namespace object containing the parsed arguments.
"""
def parse_arguments():
        parser = argparse.ArgumentParser(description="TCP Port Scanner")

        # Add argument for the target hostname or IP address
        parser.add_argument('target', type=str, 
                            help='The hostname or IP address of the machine to scan')

        args = parser.parse_args()

        return args
"""
scan_port(target, port)

Purpose:
        Scans a specified port on a target machine to determine if it is open.
        If the port is open, attempts to identify the associated service

Parameters:
        target: The hostname or IP address of the target machine
        port: The port number to be scanned

Return:
        port_status: A boolean indicating whether the port is open or closed.
        service: The name of the service associated with the open port
"""
def scan_port(target, port):
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(2)

        try:
                # Connect to the target IP and port
                result = sock.connect_ex((target, port))
                
                # If the result is 0, the port is open
                if result == 0:
                        try:
                                # Try to get the service name
                                service = socket.getservbyport(port)
                        except OSError:
                                # If there is no service associated with the 
                                # port, label it as 'N/A'
                                service = 'N/A'
                
                        sock.close()
                        return True, service
                else:
                        sock.close()
                        return False, None
                
        except socket.error as e:
                # Handle socket errors
                print(f"Error scanning port {port}: {e}")
                sock.close()
                return False, None

"""
port_looper(target)

Purpose:
        Iterates through all possible ports (0 to 65535) on a target machine
        and scans each port using the scan_port function. It gets information
        about open ports and their associated services

Parameters:
        target: The hostname or IP address of the target machine 

Return:
        A list of tuples containing information about open ports and their 
        associated services.
"""
def port_looper(target):
        open_ports = []
        
        # Scan ports in the range of 0 to 65535
        for port in range(1,65536):
                port_status, service = scan_port(target, port)
                if port_status:
                        open_ports.append((port, service))
        return open_ports

"""
write_to_file(open_ports, time)

Purpose:
        Writes the results of the port scanning process to a file named 
        "scanner.txt". It includes information about each open port, the total 
        time elapsed for the scan, and the time taken per scan

Parameters:
        open_ports: A list of tuples containing information about open ports and
                    their associated services.
        time: The total time elapsed during the port scanning process

Return:
        None
"""
def write_to_file(open_ports, time):
        # Open the file in write mode
        file = open('scanner.txt', 'w')
        # Write the information about each open port
        for port, service in open_ports:
                file.write(f"{port} ({service}) was open\n")
        
        # Write the total time elapsed
        file.write(f"time elapsed = {time:.2f}s\n")
        
        # Calculate and write the time per scan
        total_ports = 65536
        time_per_scan = time / total_ports
        file.write(f"time per scan = {time_per_scan:.4f}s\n")

        # Close the file
        file.close()

"""
main()

Purpose:
        Orchestrates the entire port scanning process by invoking necessary 
        functions to parse command-line arguments, scan ports, record timing
        information, and write the results to a file

Parameters:
        None

Return:
        None
"""
def main():
        args = parse_arguments()
        # Target IP address or hostname
        target = args.target

        # Record the start time
        start = time.time()

        # Function that loops through each port
        open_ports = port_looper(args.target)

        # Record the end time
        end = time.time()
        time_elapsed  = end - start

        # Function that writes to the file
        write_to_file(open_ports, time_elapsed)



if __name__ == "__main__":
        main()