from reader import read_log

def filter_sensitive_ports(log_data):
     list_port_sens = []
     for line in log_data:
        if line[3] == "22" or line[3] == "23" or line[3] == "3389":
            list_port_sens.append(line)
     return list_port_sens
liie = filter_sensitive_ports(read_log("network_traffic.log"))
print(len(liie))       