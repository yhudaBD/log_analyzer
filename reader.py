import csv
def read_log(file_log):
    with open(file_log , "r") as file:
        return [row for row in csv.reader(file)]
