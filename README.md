HackingHoneypotMap
======
This project tracks failed logon attempts (attacks) targeting an AWS virtual machine and displays the attempts on a worldmap; the worldmap is hosted on a site for others to see where attacks are coming from: https://ec2-18-208-44-207.compute-1.amazonaws.com/

### Softwares/Components used:
* Python
  * Pywin32 library
    * Used to read Failed RDP Logins as EventLog objects
    * EventLog object is then processed to obtain the IP address of the attacker
  * UrlLib.requests library
    * Used to pass in the IP address of the attacker into the AbstractAPI Ip Geolocation API
* HTML/Javascript
  * Used to write the website displaying attacks
  * Makes use of Google Developers' GeoCharts API
* AbstractAPI's IP Geolocation API
  * Used to read an IP address and generate a geolocation (country, longitude, latitude)
* Amazon Web Services EC2 Instance
  * Used to host the virtual machine being attacked, as well as the website displaying attacks
* Windows Event Log Viewer
  * Used to record Failed RDP Logins directed at the virtual machine
* XAMPP
  * Used to host the website
