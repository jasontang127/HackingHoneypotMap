import json
import re
import time
from datetime import date

import requests
import win32con
import win32evtlog

api_key = "c3b596ba6ab7401b9eef629eae5606ff"
#
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


# open event log

maxFreq = 1
while True:
    updated = False
    begin_time = date.today()
    print(begin_time)
    hand = win32evtlog.OpenEventLog(computer, logtype)
    events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
    print("Getting batch of logs " + str(len(events)))
    if len(events) > 0:
        maxID = events[0].RecordNumber
        try:
            freqLogFile = open("freqLogFile.txt", "r")
            freqLog = json.loads(freqLogFile.read())
            freqLogFile.close()
        except FileNotFoundError:
            print("freqLogFile doesn't exist, writing it now")
            freqLogFile = open("freqLogFile.txt", "a")
            freqLog = {}
        try:
            maxIDFile = open("maxIDFile.txt", "r")
            prevMaxID = int(maxIDFile.readline())
            maxFreq = int(maxIDFile.readline())
            print("Prev max ID: " + str(prevMaxID))
        except FileNotFoundError:  # first time running
            print("maxIDFile doesn't exist, writing it now")
            prevMaxID = -1
        finally:
            reachedMax = maxID <= prevMaxID
            if reachedMax is False:  # new entries since last log
                maxIDFile = open("maxIDFile.txt", "w")
                maxIDFile.write(str(maxID))

                jsonLogFile = open("jsonLogFile.txt", "a")

                while len(events) > 0 and (reachedMax is False):  # read each log until either end of history or previous max
                    for item in events:
                        # print("Item record number: " + str(item.RecordNumber))
                        if item.RecordNumber <= prevMaxID:
                            reachedMax = True
                            print("Reached previous max ID")
                            break
                        else:
                            if item.EventID == 4625:  # failed RDP login
                                print(f"Event time generated: " + str(item.TimeGenerated))
                                timediff = begin_time - item.TimeGenerated.date()
                                if not str(timediff)[0] == '0':
                                    print("Record is a day old, stop here")
                                    break
                                print("Time since today: " + str(timediff))
                                print(f"Event computer name: " + str(item.ComputerName))
                                ip = str(item.StringInserts[19])
                                print(f"IP address: " + ip)
                                response = requests.get(
                                    "https://ipgeolocation.abstractapi.com/v1/?api_key=" + api_key + "&ip_address=" + ip)
                                try:
                                    data_list = json.loads(response.content)
                                    country = data_list["country"]
                                    longitude = data_list["longitude"]
                                    latitude = data_list["latitude"]
                                    print("Country: " + str(country))
                                    print("Longitude: " + str(longitude))
                                    print("Latitude: " + str(latitude))
                                    json_file = json.dumps(
                                        {"IP address": ip, "Country": country, "Longitude": longitude,
                                         "Latitude": latitude})
                                    print(json_file)
                                    jsonLogFile.write(json_file + "\n")
                                    if str(country) in freqLog.keys():  # country already exists in log
                                        freqLog.update({str(country): int(freqLog[str(country)] + 1)})
                                        if maxFreq < freqLog[str(country)]:
                                            maxFreq = freqLog[str(country)]
                                    elif country is not None:  # adding country to log
                                        freqLog.update({str(country): 1})
                                    updated = True
                                except KeyError:
                                    print("API error, passing")
                                    pass
                                print(freqLog)
                                time.sleep(1)
                                print("Slept for 1 seconds")
                                print()
                    events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
                if not jsonLogFile.closed:
                    jsonLogFile.close()
                maxIDFile.write("\n"+str(maxFreq))
                maxIDFile.close()

    print("Max ID: " + str(maxID))
    
    # if freqLogFile updated, reset freqLogFile and update with freqLog
    if updated is True:
        print("New attacks, updating freqLogFile")
        freqLogFile = open("freqLogFile.txt", "w").close()  # resetting file to overwrite
        freqLogFile = open("freqLogFile.txt", "w")
        freqLogFile.write(json.dumps(freqLog))  # write to freqLogFile using freqLog dictionary
        freqLogFile.close()

    payloadJS = open("payload.js", "w")  # writing javascript payload to be used in HTML page
    payloadJS.write("var payload = [\n['Country','Frequency','Area Percentage'],\n")
    print("maxFreq: " + str(maxFreq))
    for x in freqLog:  # write to javascript payload by looping through freqLog dictionary
        payloadJS.write(
            "['" + str(x) + "', " + str(freqLog[x]) + ", " + str((int(freqLog[x]) / int(maxFreq)) * 100) + "],\n")
    payloadJS.write("];")
    payloadJS.close()

    print("Sleeping for 1 minutes")
    time.sleep(60)
    print("Slept for 1 minutes----------------------------------")

