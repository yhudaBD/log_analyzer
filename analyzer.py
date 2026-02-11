from reader import read_log

def get_ip_in_log(log_data):
    suspects_ip = []
    for line in log_data:
      ip = line[1]
      if not ip.startswith("10.") and not ip.startswith("192.168."):
         suspects_ip.append(ip)
         
    return suspects_ip 

log  = get_ip_in_log(read_log("network_traffic.log"))
print(len(log))

