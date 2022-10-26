import sys
from sslyze import *

# Create a scan request and add it to the list of requests for scannig
denied_list = []
scan_list = []
total = 0
all_IP = 0
v0 = 0
s0 = set()
v1 = 0
s1 = set()
v2 = 0
s2 = set()
v3 = 0
s3 = set()

for line in sys.stdin:
    all_IP += 1
    line = line.strip()
    host, port = line.split(":")[0], line.split(":")[1]
    try:
        server_location = ServerNetworkLocation(hostname=host, port=port)
        scan_list.append(ServerScanRequest(server_location=server_location, scan_commands={}))
        # print("Added " + line + " to the scan list")
    except ServerHostnameCouldNotBeResolved:
        # DNS lookup failed (invalid Host)
        # print("DNS failed for " + line)+
        denied_list.append(line)
        pass
print(f"All host are added to the list, except the following list.\n{denied_list}")
# Queue (run) all the scans
print(f"\nScanning...\n")
scanner = Scanner()
scanner.queue_scans(scan_list)

# Process the results for each server
# Write to the output file
print(f"Scan Completed.\n\tListing the Results.\n")
for scan_result in scanner.get_results():
    if scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        # Couldn't connect to service
        print(f"{scan_result.server_location.hostname}:{scan_result.server_location.port}\t\t::\tfailed to connect.")
        pass
    # Since we were able to run the scan, scan_result is populated
    else:
        total += 1
        version = str(scan_result.connectivity_result.highest_tls_version_supported).split(".")[1]
        if version == "TLS_1_3":
            v3 += 1
            s3.add(str(scan_result.connectivity_result.cipher_suite_supported))
        elif version == "TLS_1_2":
            v2 += 1
            s2.add(str(scan_result.connectivity_result.cipher_suite_supported))
        elif version == "TLS_1_1":
            v1 += 1
            s1.add(str(scan_result.connectivity_result.cipher_suite_supported))
        elif version == "TLS_1_0":
            v0 += 1
            s0.add(str(scan_result.connectivity_result.cipher_suite_supported))
        # print(f"{scan_result.server_location.hostname}:{scan_result.server_location.port}\t::\t{version}:{scan_result.connectivity_result.cipher_suite_supported}")

print(f"Number of All devices:\t{all_IP}")
print(f"\nNumber of Responded Devices:\t{total}")
print(f"\tThe Number of Devices Supported TLSv1.0: {v0}\t:: Percentage:\t{round(float(v0/total*100), 2)}%")
print(f"\tThe Number of Devices Supported TLSv1.1: {v1}\t:: Percentage:\t{round(float(v1/total*100), 2)}%")
print(f"\tThe Number of Devices Supported TLSv1.2: {v2}\t:: Percentage:\t{round(float(v2/total*100), 2)}%")
print(f"\tThe Number of Devices Supported TLSv1.3: {v3}\t:: Percentage:\t{round(float(v3/total*100), 2)}%")
print(f"\n\nList of Ciphersuites Used With TLSv1.0:\n{s0}")
print(f"\nList of Ciphersuites Used With TLSv1.1:\n{s1}")
print(f"\nList of Ciphersuites Used With TLSv1.2:\n{s2}")
print(f"\nList of Ciphersuites Used With TLSv1.3:\n{s3}")