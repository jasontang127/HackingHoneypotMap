HackingHoneypotMap
======
This project tracks failed logon attempts (attacks) targeting an AWS virtual machine and displays the attempts on a worldmap; the worldmap is hosted on a site for others to see where attacks are coming from: https://ec2-50-19-106-29.compute-1.amazonaws.com/

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
  * Auto-refreshses the page to keep the site up to date with new logins
* AbstractAPI's IP Geolocation API
  * Used to read an IP address and generate a geolocation (country, longitude, latitude)
* Amazon Web Services EC2 Instance
  * Used to host the virtual machine being attacked, as well as the website displaying attacks
* Windows Event Log Viewer
  * Used to record Failed RDP Logins directed at the virtual machine on port 3389
* XAMPP
  * Used to host the website
  
A screenshot of the page is included below:
![image](https://user-images.githubusercontent.com/45743962/189778581-41feec81-0f3c-43d4-8f26-80bc0de9af69.png)

