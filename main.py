import json
import re
import time
from datetime import date

import requests
import win32con
import win32evtlog

api_key = "c3b596ba6ab7401b9eef629eae5606ff"


# print(response.status_code)
# print(response.content)


def date2sec(evt_date):
    '''

    This function converts dates with format

    '12/23/99 15:54:09' to seconds since 1970.

    '''

    regexp = re.compile('(.*)\\s(.*)')  # store result in site

    reg_result = regexp.search(evt_date)

    date = reg_result.group(1)

    the_time = reg_result.group(2)

    date_list = date.split()

    (mon, day, yr) = (date_list[0], date_list[1], date_list[2])

    print(date)
    print(the_time)

    time_list = date_list[3].split(":")

    (hr, min, sec) = (time_list[0], time_list[1], time_list[2])

    tup = [yr, mon, day, hr, min, sec, 0, 0, 0]

    sec = time.mktime(tup)

    return sec


####Main program

# initialize variables

flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ
# This dict converts the event type into a human readable form

evt_dict = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
            win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
            win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
            win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}

computer = 'localhost'

logtype = 'Security'

# begin_sec = time.time()

# begin_time = time.strftime('%H:%M:%S  ', time.localtime(begin_sec))

begin_time = date.today()
print(begin_time)
# open event log



while True:
    hand = win32evtlog.OpenEventLog(computer, logtype)
    events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
    print("Getting batch of logs " + str(len(events)))

    if len(events) > 0:
        maxID = events[0].RecordNumber
        try:
            maxIDFile = open("maxIDFile.txt", "r")
            prevMaxID = int(maxIDFile.readline())
            print("Prev max ID: " + str(prevMaxID))
        except FileNotFoundError:
            print("File doesn't exist, writing it now")
            prevMaxID = -1
        finally:
            reachedMax = maxID <= prevMaxID
            if reachedMax is False:
                maxIDFile = open("maxIDFile.txt", "w")
                maxIDFile.write(str(maxID))
                maxIDFile.close()

    while len(events) > 0 and (reachedMax is False):
        for item in events:
            print("Item record number: " + str(item.RecordNumber))
            if item.RecordNumber <= prevMaxID:
                reachedMax = True
                print("Reached previous max ID")
                break
            else:
                if item.EventID == 4625:
                    # print(f"Event time generated: " + str(item.TimeGenerated))
                    # # if int(str(begin_time - item.TimeGenerated.date()).split()[0]) > 7:
                    # #     print("This happened within the last week!")
                    # print("Time since today: " + str(begin_time - item.TimeGenerated.date()))
                    # print(f"Event computer name: " + str(item.ComputerName))
                    # ip = str(item.StringInserts[19])
                    # print(f"IP address: " + ip)
                    # response = requests.get(
                    #     "https://ipgeolocation.abstractapi.com/v1/?api_key=" + api_key + "&ip_address=" + ip)
                    # data_list = json.loads(response.content)
                    # country = data_list["country"]
                    # longitude = data_list["longitude"]
                    # latitude = data_list["latitude"]
                    # print("Country: " + country)
                    # print("Longitude: " + str(longitude))
                    # print("Latitude: " + str(latitude))
                    # print()
                    # json_file = json.dumps({"IP address": ip, "Country": country, "Longitude": longitude, "Latitude": latitude})
                    # print(json_file)
                    time.sleep(1)
                    print("Slept for 1 seconds")
        events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
    time.sleep(5)
    print("Slept for 5 seconds----------------------------------")
# print
# logtype, ' events found in the last 8 hours since:', begin_time
#
# try:
#
#     events = 1
#
#     while events:
#
#         events = win32evtlog.ReadEventLog(hand, flags, 0)
#
#         for ev_obj in events:
#
#             # check if the event is recent enough
#
#             # only want data from last 8hrs
#
#             the_time = ev_obj.TimeGenerated.Format()
#
#             # seconds = date2sec(the_time)
#             #
#             # if seconds < begin_sec - 28800: break
#
#             if ev_obj.EventID == 4625:
#                 # data is recent enough, so print it out
#
#                 computer = str(ev_obj.ComputerName)
#
#                 cat = str(ev_obj.EventCategory)
#
#                 src = str(ev_obj.SourceName)
#
#                 record = str(ev_obj.RecordNumber)
#
#                 evt_id = str(winerror.HRESULT_CODE(ev_obj.EventID))
#
#                 evt_type = str(evt_dict[ev_obj.EventType])
#
#                 msg = str(win32evtlogutil.SafeFormatMessage(ev_obj, logtype))
#
#                 print(string.join((the_time, computer, src, cat, record, evt_id, evt_type, msg[0:15]), ':'))
#
#             # if seconds < begin_sec - 28800:
#             #     break  # get out of while loop as well
#
#         win32evtlog.CloseEventLog(hand)
# #
# except:
#     print("blah")
#     print(traceback.print_exc(sys.exc_info()))
