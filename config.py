from reader import read_log
from datetime import datetime
from main import log_data
#1.3
def filter_sensitive_ports(log_data):
     list_port_sens = []
     for line in log_data:
        if line[3] == "22" or line[3] == "23" or line[3] == "3389":
            list_port_sens.append(line)
     return list_port_sens
liie = filter_sensitive_ports(read_log("network_traffic.log"))


#3.1
hours = list(map(lambda line: datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S").hour, log_data))

#3.3
Port_Filtering = list(
    filter(lambda line:
     line[3] == "22" or line[3] == "23" or line[3] == "3389" , log_data ))
