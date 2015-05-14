NmaPY-nmap-autoscanner
======================

NmaPY will do a Nmap scan of all the IPs mentioned in a file and will save the results in a .csv file 



Usage (Commandline):
$ : python NmaPy.py –Port (port range) –Target IP_list.

Example:
$ : python NmaPy.py –Port 0-65535 –Target Machine_IP.list

The script will then create a directory names Machine_IP.list/ and create two files NmaPy-Scan.txt and NmaPy.csv
NmaPy-Scan.txt – Stores the verbose content (Not really useful)
NmaPy-Scan.csv – Stores the values of all open ports and the services running in csv format.

