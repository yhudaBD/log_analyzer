from reader import read_log

def get_ip_in_log(log_data):
    suspects_ip = []
    for line in log_data:
      ip = line[1]
      if not ip.startswith("10.") and not ip.startswith("192.168."):
         suspects_ip.append(ip)
         
    return suspects_ip 

log  = get_ip_in_log(read_log("network_traffic.log"))


def tag_logs_by_size(log_data):
   tagged_logs = []
   for line in log_data:
      if int(line[5]) > 5000:
         line.insert(0 ,"LARGE")
         tagged_logs.append(line)

      else:
         line.insert(0, "NORMAL" ) 
         tagged_logs.append(line)
   return tagged_logs  
line = tag_logs_by_size(read_log("network_traffic.log"))

