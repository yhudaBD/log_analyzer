from reader import read_log
from main import log_data

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

def list_ip(log_data):
     list_ip = [log[1] for log in log_data]
     return list_ip

def cuonter_ip(list_ip):
    my_dict = {}
    for line in list_ip:
      if line in my_dict:
        my_dict[line] += 1
      else:
       my_dict[line] = 1
    return my_dict
d = cuonter_ip(list_ip(log_data))

   
def cuonter_ports(log_data):
   dict_port = {log[3] : log[4] for log in log_data}
   return dict_port
di = cuonter_ports(log_data)
print(di)
