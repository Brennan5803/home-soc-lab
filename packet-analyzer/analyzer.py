from scapy.all import sniff, TCP, IP #scapy scrapes the network to get usable data
import time #to track what time incedents happened
import logging #to log the incedents

#configs the logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

synTracker ={} # dict to track the syn packages
tracker ={} #tracks the ips
alerted = set() #tracks which ips set of the alert
susPorts = {23,445,3389,1433,4444} #a set of suspicious ports

def analizePackets(packets): #main function

    if TCP in packets and IP in packets: #checks if both tcp and ip are in packets
        src_ip = packets[IP].src
        ports = packets[TCP].dport
        
        
        if ports in susPorts: #checks if the port is suspicious
            logging.warning(f"suspicious port {ports}") 

        
        if packets[TCP].flags == "S": # if the tcp carrys the syn
            if src_ip not in synTracker: 
                synTracker[src_ip] = {"count":1, "time":time.time()} #dict to tract the number of syn packages and a timer
            else:
                synTracker[src_ip]["count"]+=1 
        
        
        if src_ip in synTracker: #checks if ip is already in dict
             #checks if 10 seconds have passed and if more the 10 syn packages have come in that time
            if time.time() - synTracker[src_ip]["time"] < 10 and synTracker[src_ip]["count"] >10:
            
                logging.warning(f"syn attack from {src_ip}") #logs attack
                #resets the timer and counter to prevent multiple logs from one attack
                synTracker[src_ip]["time"] = 0 
                synTracker[src_ip]["count"] = 0

            #resets of no attack happens    
            elif time.time() - synTracker[src_ip]["time"] >= 10:
                synTracker[src_ip]["time"] = 0
                synTracker[src_ip]["count"] = 0



        if src_ip not in tracker: #if ip not in tracker
            tracker[src_ip] = set() #creates a set so we can add our ports


        tracker[src_ip].add(ports)

        #checks if there are more than ten ports coming from one ip and that it hasnt already been detected
        if len(tracker[src_ip])>10 and src_ip not in alerted : 
            logging.warning(f"PORT SCAN DETECTED from {src_ip} {len(tracker[src_ip])} unique ports")#logs it
            alerted.add(src_ip)#adds the ip to the alerted set so attack cant be logged twice

#this gets the data that we need and callbacks our funtction to keep it running and wld0 is the type of internet i have
sniff(prn=analizePackets, iface='wld0')