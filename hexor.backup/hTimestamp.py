import time
import datetime


# from and to timestamp

date = "2022/05/21 2:12:32"
output = time.mktime(datetime.datetime.strptime(date, "%Y/%m/%d %I:%M:%S").timetuple())
print(output)

print(datetime.datetime.fromtimestamp(output))