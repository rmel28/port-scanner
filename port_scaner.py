# Project Overview and Importance
# Port scanning allows you to locate open doors on a computer or network – hackers can use these ports to find weak points to get into


#important concepts
#IP address- Home address for your device - allows the data to be sent to your device like mail being sent to your home 
#Ports- like doors inside your house every service on device is running on a different port 
#Threading- allows the program to run multiple parts at one time parallel to each other 

import threading
import socket
import time 
from tkinter import ttk, scrolledtext
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
import ipaddress

max_workers = 100 

def generate_port_chunks(port_range):
    '''
    Splits a string like '1-1000' into smaller chunks
    returns a list of those split chunks
    '''
    port_ranges = port_range.split('-') # splits the string into 2 pieces - "1-1000" -> ["1", "1000"]
    port_chunks = [] # Empty list to store the split chunks
    start_port = int(port_ranges[0]) #converts those split strings into an integer
    end_port = int(port_ranges[1])

    chunk_size =((end_port - start_port) // max_workers) #figures out how many ports each thread should scan if 1000 ports with 100 workers then 10 each 
 
    for i in range(max_workers): # Loops through max_workers (100), so it will run 100 times
        start = start_port + (chunk_size * i) #starting point for the chunk
        end = start + chunk_size #end port
        port_chunks.append((start, end)) 
    return port_chunks 

def scan(ip_address, port_chunk):
    '''
    purpose: scans a range of port on an IP address to see which ones are open 
    Parameters: Ip_address - is the ip_address of which we are scanning 
                port_chunk - is the range which we are scanning
    '''
    print(f"[~] Scanning {ip_address} from {port_chunk[0]} to {port_chunk[1]}.")

    for port in range(int(port_chunk[0]), int(port_chunk[1])):

        try:
            scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# Creates a network connection 
            scan_socket.settimeout(2) # If a connection does not happen in 2 seconds, it times out 

            scan_socket.connect((ip_address, port)) #tries to connect to port and address to test if open
            print(f"[!] Port {port} is open")

        except Exception as e:
            print(f"[x] Error on port {port}: {e}")


def main():
    '''
    purpose: scans the target IP address over a range of ports
    '''
    ip_address = input("IP address: ")
    port_range = input("Port range: ")

    port_chunks = generate_port_chunks(port_range) #calls generate_port_chunks function so each thread can scan a certain range

    start_time = time.time()  

    with ThreadPoolExecutor(max_workers = max_workers) as executor: # Creates the threads; 'with' will automatically clean them up
        executor.map(scan, [ip_address] * len(port_chunks), port_chunks) # Runs the scan function in parallel threads; [ip_address] * n ensures each thread gets the IP

    end_time = time.time() 
    print(f"scanned {port_range} ports in {end_time - start_time} seconds.")

def start_gui(): 
    root = tk.Tk() 
    root.title("Port Scanner")

    ip_label = ttk.Label(root, text="IP Address:")
    ip_label.grid(column=0, row=0, padx=5, pady=5)
    ip_entry = ttk.Entry(root) 
    ip_entry.grid(column=1, row=0, padx=5, pady=5) 

    port_label = ttk.Label(root, text="Port Range (e.g. 1-1000):") 
    port_label.grid(column=0, row=1, padx=5, pady=5)
    port_entry = ttk.Entry(root)
    port_entry.grid(column=1, row=1, padx=5, pady=5)

    output = scrolledtext.ScrolledText(root, width=60, height=20) 
    output.grid(column=0, row=3, columnspan=2, padx=5, pady=5)

    def scan_gui_threaded(ip_address, port_chunk, log):
        '''
        purpose: GUI-compatible version of scan() using a logging callback
        '''
        for port in range(int(port_chunk[0]), int(port_chunk[1])):
            try:
                scan_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                scan_socket.settimeout(2)
                scan_socket.connect((ip_address, port))
                log(f"[!] Port {port} is open\n")
            except Exception as e:
                log(f"[x] Error on port {port}: {e}\n")

    def start_scan():
        def do_scan():
            ip_address = ip_entry.get()
            port_range = port_entry.get() 

            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                output.after(0, output.insert, tk.END, "[!] Invalid IP address.\n")
                return

            try:
                port_chunks = generate_port_chunks(port_range) 
            except:
                output.after(0, output.insert, tk.END, "[!] Invalid port range. Use format like 1-1000.\n") 
                return

            start_time = time.time() 
            output.after(0, output.insert, tk.END, f"Starting scan on {ip_address}...\n") 

            def log_result(msg): 
                output.after(0, output.insert, tk.END, msg) 
                output.after(0, output.see, tk.END)

            with ThreadPoolExecutor(max_workers=max_workers) as executor: 
                futures = [executor.submit(scan_gui_threaded, ip_address, chunk, log_result) for chunk in port_chunks]
                for future in futures: 
                    future.result() 

            end_time = time.time() 
            log_result(f"\nScan finished in {end_time - start_time:.2f} seconds\n")

        threading.Thread(target=do_scan).start()

    scan_button = ttk.Button(root, text="Start Scan", command=start_scan)
    scan_button.grid(column=0, row=2, columnspan=2, pady=10)



    root.mainloop()
if __name__ == '__main__':
    start_gui()