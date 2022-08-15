import json
import re
import time
from datetime import date

import requests
import win32con
import win32evtlog

api_key = ""

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

begin_time = date.today()
print(begin_time)
# open event log


maxFreq = 0
while True:
    hand = win32evtlog.OpenEventLog(computer, logtype)
    events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
    print("Getting batch of logs " + str(len(events)))
    if len(events) > 0:
        maxID = events[0].RecordNumber
        try:
            freqLogFile = open("freqLogFile.txt", "r")
            freqLog = json.loads(freqLogFile.read())
            freqLogFile.close()
            freqLogFile = open("freqLogFile.txt", "w")
        except FileNotFoundError:
            print("freqLogFile doesn't exist, writing it now")
            freqLogFile = open("freqLogFile.txt", "w")
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

                while len(events) > 0 and (reachedMax is False): # read each log until either end of history or previous max
                    for item in events:
                        # print("Item record number: " + str(item.RecordNumber))
                        if item.RecordNumber <= prevMaxID:
                            reachedMax = True
                            print("Reached previous max ID")
                            break
                        else:
                            if item.EventID == 4625: # failed RDP login
                                print(f"Event time generated: " + str(item.TimeGenerated))
                                print("Time since today: " + str(begin_time - item.TimeGenerated.date()))
                                print(f"Event computer name: " + str(item.ComputerName))
                                ip = str(item.StringInserts[19])
                                print(f"IP address: " + ip)
                                response = requests.get(
                                    "https://ipgeolocation.abstractapi.com/v1/?api_key=" + api_key + "&ip_address=" + ip)
                                data_list = json.loads(response.content)
                                country = data_list["country"]
                                longitude = data_list["longitude"]
                                latitude = data_list["latitude"]
                                print("Country: " + str(country))
                                print("Longitude: " + str(longitude))
                                print("Latitude: " + str(latitude))
                                print()
                                json_file = json.dumps(
                                    {"IP address": ip, "Country": country, "Longitude": longitude,
                                     "Latitude": latitude})
                                print(json_file)
                                jsonLogFile.write(json_file + "\n")

                                if str(country) in freqLog.keys():
                                    print("country is in keys; maxfreq: " + str(maxFreq) + " freqLogCountry: " + str(
                                        freqLog[str(country)]))
                                    freqLog.update({str(country): int(freqLog[str(country)] + 1)})
                                    if maxFreq < freqLog[str(country)]:
                                        maxFreq = freqLog[str(country)]
                                else:
                                    freqLog.update({str(country): 1})
                                print("country is in keys; maxfreq: " + str(maxFreq) + " freqLogCountry: " + str(
                                    freqLog[str(country)]))
                                print(freqLog)
                                time.sleep(1)
                                print("Slept for 1 seconds")
                    events = win32evtlog.ReadEventLog(hand, flags, 0, 8192)
                if not jsonLogFile.closed:
                    jsonLogFile.close()
                maxIDFile.write("\n"+str(maxFreq))
                maxIDFile.close()
    freqLogFile.write(json.dumps(freqLog))
    freqLogFile.close()

    payloadJS = open("payload.js", "w")
    payloadJS.write("var payload = [\n['Country','Frequency','Area Percentage'],\n")
    print("maxFreq: " + str(maxFreq))
    for x in freqLog:
        payloadJS.write(
            "['" + str(x) + "', " + str(freqLog[x]) + ", " + str((int(freqLog[x]) / int(maxFreq)) * 100) + "],\n")
    payloadJS.write("];")
    payloadJS.close()

    print("Sleeping for 1 minutes")
    time.sleep(60)
    print("Slept for 1 minutes----------------------------------")

