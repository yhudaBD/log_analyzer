import csv

def read_log(log_data):
    with open(log_data , "r") as file:
        return [row for row in csv.reader(file)]
