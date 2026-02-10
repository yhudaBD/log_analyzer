from reader import read_log

def get_ip_in_log(log_data):
    counter = 0
    suspects_ip = []
    #ip = log_data[1]
    for line in log_data:
      ip = line[1]
      if not ip.startswith("10.") and not ip.startswith("192.168."):
         suspects_ip.append(ip)
         counter += 1
    return suspects_ip ,counter

log , count = get_ip_in_log(read_log("network_traffic.log"))
print(f"Total entries: {count}")
for ip in set(log):   
 occurrence = log.count(ip)
 print(f"IP Address: {ip} | Occurrences: {occurrence}")
