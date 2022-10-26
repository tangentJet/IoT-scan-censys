import sys
import time
from sslyze import *
import sslyze

# Create a scan request and add it to the list of requests for scannig
scan_list = []
denied_list = []
all_IP = 0
total = 0
mtls = 0

# print(sslyze.__file__)
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
        # print("DNS failed for " + line)
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
        # print(f"{scan_result.server_location.hostname}:{scan_result.server_location.port}\t\t::\tfailed to connect.")
        pass
    # Since we were able to run the scan, scan_result is populated
    else:
        # print(scan_result.connectivity_result)
        total += 1
        if scan_result.connectivity_result.client_auth_requirement != ClientAuthRequirementEnum.DISABLED:
            # print(f"{scan_result.server_location.hostname}:{scan_result.server_location.port}\t\t::\tmTLS Supported.")
            mtls += 1
        else:
            # print(f"{scan_result.server_location.hostname}:{scan_result.server_location.port}\t\t::\tmTLS Not Supported.")
            pass
    # time.sleep(0.51)

print(f"Number of All devices:\t{all_IP}")
print(f"\nNumber of Responded Devices:\t{total}")
print(f"Number of Devices Supported mTLS:\t{mtls}\t:: Percentage of Devices Support Mutual TLS:\t{round(float(mtls/total*100), 2)}%")

        
