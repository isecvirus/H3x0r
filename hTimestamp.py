import re
import time
import datetime

months_name = {1: 'January', 2: 'February', 3: 'March', 4: 'April', 5: 'May', 6: 'June', 7: 'July', 8: 'August', 9: 'September', 10: 'October', 11: 'November', 12: 'December'}

def Date2Timestamp(date_sep: str = "/", time_sep: str = ":", year: str = datetime.datetime.now().year,
                   month: str = datetime.datetime.now().month, day: str = datetime.datetime.now().day,
                   hour: str = datetime.datetime.now().hour, minute: str = datetime.datetime.now().minute,
                   second: str = datetime.datetime.now().second):
    try:

        date = "%s{0}%s{0}%s %s{1}%s{1}%s".format(date_sep, time_sep) % (year, month, day, hour, minute, second)

        output = time.mktime(datetime.datetime.strptime(date, "%Y/%m/%d %I:%M:%S").timetuple())
        return int(output)
    except Exception:
        return ''
def Timestamp2Date(timestamp:int):
    try:
        timestamp = int(re.findall("\d+", str(timestamp))[0])
        return datetime.datetime.fromtimestamp(int(timestamp))
    except Exception:
        return ''