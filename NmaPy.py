######### NmaPy-Auto Nmap Scan Script ######
######### Author : Jovin Lobo ##############
######### Email : j0k3r@null.co.in / jovyn4590@gmail.com #####
######### Twitter : @7h3_j0k3r ############

#!/usr/bin/env python
import nmap, sys, os     
import shutil
import time, datetime
import argparse
import csv

# Printing NmaPY Uage /Help >>
# usage$: python NmaPy.py -Port (port-Range) -Target (File_with_target_IPs)
# Example: python NmaPy.py -Port 0-65535 -Target Aujas_IP.txt
argp = argparse.ArgumentParser(prog='python NmaPy.py',usage='%(prog)s -Port [port_range] -Target [target_file]',description='Eg: python NmaPy.py -Port 0-1000 -Target IP_list.txt . **NmaPy.py** is a python script that will do a Nmap scan on all the IPs mentioned in the target_IP_file and save the results in a .txt and .csv files.',epilog="That's All Folks")
argp.add_argument('-Port', help='enter port range Eg. 0-65535', nargs='+')
argp.add_argument('-Target', help='enter a file Eg. MyIP.txt', nargs='+')
if len(sys.argv)!=5:
    argp.print_help()
    sys.exit(1)
args = argp.parse_args()

timestamp = time.time()  # Timestamp not used anywhere 
nmapy_dir = "NmaPy-Scan_for_" + str(sys.argv[4])  # Creates a directory with the same name as that of the filename (eg: Aujas_IP.txt/)

# Check if Dir exixts, and if it exists ask user if he wants to overwrite it. If he says a directory with the same name ending with .Copy will be created
if not os.path.exists(nmapy_dir):
	os.mkdir(nmapy_dir)
else:
	check_dir = raw_input('Directory ' + nmapy_dir + 'Exists !!.\n Do you wish to Overrite ? (Press Y for yes , Else press any other Key...)')
	check_dir = str(check_dir.lower())
	if check_dir in ['y', 'yes']:
		shutil.rmtree(nmapy_dir)
		os.mkdir(nmapy_dir)
	else:
		nmapy_dir = str(nmapy_dir + ".Copy")
		os.mkdir(nmapy_dir)

# Creating two files inside the directory ; NmaPy-Scan.txt stores the verbose, and NmaPy-Scan.csv stores the values in .csv format	
scan_result_txt_file = os.path.join(nmapy_dir,"NmaPy-Scan.txt")
scan_result_csv_file = os.path.join(nmapy_dir,"NmaPy-Scan.csv")

#import csv
# write values to the .csv file
with open(scan_result_csv_file, 'wb') as csvfile:
	csvwrite = csv.writer(csvfile, delimiter=',',dialect='excel')	
	csvwrite.writerow(['IP Address', 'Port', 'Protocol', 'State', 'Service'])
	csvwrite.writerow(['', '', '', '', ''])

port_list = sys.argv[2];
target_file  = open(sys.argv[4],"r")  # Open the target file to read IPs from it.
for IP in target_file:
	x = nmap.PortScanner()        # Creates an Nmap Instance
	IP = IP.strip('\r\n')
	IP = IP.strip()               # Strip the newline and whitespaces from each row of the file
	x.scan(IP, port_list)
	#print x.commandline()          # This will show you what Nmap command is running in the backend. (nmap -sS -Pn -Ox - -p 0-65535 target_IP)
	ip_state = x[IP].state()
	#Ping_resp = os.system("ping -c 1 " + str(IP))       # Not required to Ping. 
	#print Ping_resp 
	if ip_state == "up":
		print "The STATE of " + IP + " is " + str(ip_state)    # Print state of IP (up) 
		with open(scan_result_csv_file, 'ab') as csvfile:       # Print to csv file only if the IP is UP.
	        	csvwrite = csv.writer(csvfile, delimiter=',',dialect='excel')
        		csvwrite.writerow([IP]+['','','',''])

		first_line = " Scanning " + IP + " for Ports " + port_list ;
		print (first_line)
		#x = nmap.PortScanner()
		#x.scan(IP, port_list)
		print (" Hostname :" + x[IP].hostname())
		print ("State :" + x[IP].state())
		scanned_protocols = (x[IP].all_protocols())
		for protocol in scanned_protocols:
			print ("Scanned Protocol:" + protocol)
			print ("-------------------------------------------")	
		all_tcp_ports = (x[IP].all_tcp()) 
        	print ("The following TCP ports are open \n")
		print ("IP Address: PORT -- STATE -- SERVICE \n")
		#scan_result_txt_file = str(datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'))+ ".txt"
        	scan_result_txt = open(scan_result_txt_file, "wb")
		scan_result_txt.write(" Hostname :" + x[IP].hostname())
		scan_result_txt.write("State :" + x[IP].state())
		scan_result_txt.write("The following TCP ports are open \n")
        	scan_result_txt.write("IP Addr : PORT - STATE - SERVICE \n\n")
		for tcp_port in all_tcp_ports:
			tcp_port_str = str(tcp_port)
			tcp_port_info = (x[IP]['tcp'][tcp_port])
			tcp_port_state = str(x[IP]['tcp'][tcp_port]['state'])
			tcp_port_name = str(x[IP]['tcp'][tcp_port]['name'])
			#print (tcp_port_info)
			print (IP + ":" + tcp_port_str + " ---- " + x[IP]['tcp'][tcp_port]['state'] + " ---- " + x[IP]['tcp'][tcp_port]['name'] +"\n")
			
			if (str(x[IP]['tcp'][tcp_port]['state']).lower) != 'closed':
				with open(scan_result_csv_file,'a') as csvfile:	
					fd = csv.writer(csvfile, delimiter=',',dialect='excel')
					fd.writerow([' ']+[tcp_port_str]+['TCP']+[tcp_port_state]+[tcp_port_name])
	
			scan_result_txt.write(IP + ":" + tcp_port_str + " " + x[IP]['tcp'][tcp_port]['state'] + " " + x[IP]['tcp'][tcp_port]['name'] +"\n")	
		scan_result_txt.write("\n----------------------------------------------------------------------\n")	
		print ("-------------------------------------------")

                # Ignore the UDP ports as of now. 
		'''
		all_udp_ports = (x[IP].all_udp())
        	print ("The following UDP ports are open \n")
		print ("IP Address: PORT -- STATE -- SERVICE \n")
		scan_result_txt.write("The following UDP ports are open \n")
        	scan_result_txt.write("IP Addr : PORT -- STATE -- SERVICE \n")
        	for udp_port in all_udp_ports:
                	udp_port_str = str(udp_port)
			udp_port_state = str(x[IP]['udp'][tcp_port]['state'])
                	udp_port_name = str(x[IP]['udp'][tcp_port]['name'])
			scan_result_txt.write(IP + ":" + udp_port_str + " " + x[IP]['udp'][udp_port]['state'] + " " + x[IP]['udp'][udp_port]['name'])
			print (IP + ":" + udp_port_str + " ---- " + x[IP]['udp'][udp_port]['state'] + " ---- " +x[IP]['udp'][udp_port]['name'] + "\n")

			with open(scan_result_csv_file,'a') as csvfile:
                        	fd = csv.writer(csvfile, delimiter=',',dialect='excel')
				fd.writerow([' ']+[udp_port_str]+['UDP']+[udp_port_state]+[udp_port_name])
	
		with open(scan_result_csv_file,'a') as csvfile:
                     	fd = csv.writer(csvfile, delimiter=',',dialect='excel')
                        fd.writerow(['','','','',''])
			fd.writerow(['','','','',''])
	
 		print ("-------------------------------------------")
                '''
 	else:
		print "Oh Darn !! Seems like the State of " + IP + " is " + str(ip_state)
	
scan_result_txt.close()
print x.scanstats()
print "Scanned results stored in file", scan_result_txt.name
print "Scanned results in CSV Format in file", scan_result_csv_file
print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \n")
	
