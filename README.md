A simple packet sniffer built using scapy and scapy-http libraries. It listens to http traffic and looks for URLs and credentials entered into insecure web forms.

In order to work this packet sniffer requires scapy_http installed:
```
pip install scapy_http
```
Usage: 
```
sudo packet_sniffer.py -i [INTERFACE]
```
or
```
sudo packet_sniffer.py --interface [INTERFACE]
```
ex.
```
sudo python packet_sniffer.py -i enp2s0
```
```
Sniffing on enp2s0
[+] HTTP Request ==> testphp.vulnweb.com/userinfo.php
[+] Found username and/or password! ==> uname=hafasec&pass=Passw0rd123
[+] HTTP Request ==> testphp.vulnweb.com/login.php
[+] HTTP Request ==> testphp.vulnweb.com/artists.php
[+] HTTP Request ==> testphp.vulnweb.com/login.php
[+] HTTP Request ==> connectivity-check.ubuntu.com/
[+] HTTP Request ==> testphp.vulnweb.com/AJAX/index.php
[+] HTTP Request ==> testphp.vulnweb.com/AJAX/categories.php
[+] HTTP Request ==> testphp.vulnweb.com/AJAX/showxml.php
```
