from scapy.all import rdpcap, TCP

pcap_file = "security-footage-1648933966395.pcap"
packets = rdpcap(pcap_file) # Read the pcap file

jpeg_start = b'\xff\xd8' # Start of JPEG file
jpeg_end = b'\xff\xd9' # End of JPEG file

# Extract all TCP payloads
payloads = []
for pkt in packets: # Iterate through all packets
    if pkt.haslayer(TCP): # Check if the packet has a TCP layer
        raw = bytes(pkt[TCP].payload) # Extract the raw TCP payload
        if raw: # Check if the payload is not empty
            payloads.append(raw) # Append the payload to the list

# Join all TCP payloads into a single binary stream
data = b''.join(payloads)

# Find and extract JPEG images
i = 0
pos = 0
while True: # Loop until no more JPEG images are found
    start = data.find(jpeg_start, pos) # Find the start of the JPEG image
    if start == -1: # If no more start marker is found, break the loop
        break
    end = data.find(jpeg_end, start) # Find the end of the JPEG image
    if end == -1: # If no more end marker is found, break the loop
        break
    end += 2 
    with open(f"image_{i:04d}.jpg", "wb") as f: # Open a new file to write the image
        f.write(data[start:end]) # Write the image data to the file
    i += 1
    pos = end

print(f"{i} found image.")
