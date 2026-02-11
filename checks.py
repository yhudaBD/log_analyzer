from reader import read_log

def filter_high_traffic(log_data):
    findings = []
    for line in log_data:
        if int(line[5]) > 5000 :
          findings.append(line)
    return findings
line = filter_high_traffic(read_log("network_traffic.log"))
print(len(line))      