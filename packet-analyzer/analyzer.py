from scapy.all import sniff, TCP, IP
import time
import logging

logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

synTracker ={}
packets = {}
tracker ={}
alerted = set()
susPorts = {23,445,3389,1433,4444}

def printSyn(packets):

    if TCP in packets and IP in packets:
        src_ip = packets[IP].src
        ports = packets[TCP].dport
        #print(src_ip, ports)
        if ports in susPorts:
            logging.warning(f"suspicious port {ports}")

        if packets[TCP].flags == "S":
            if src_ip not in synTracker: 
                synTracker[src_ip] = {"count":1, "time":time.time()}
            else:
                synTracker[src_ip]["count"]+=1
        if src_ip in synTracker:
            if time.time() - synTracker[src_ip]["time"] < 10 and synTracker[src_ip]["count"] >10:
                print(f"syn attack from {src_ip}")
                logging.warning(f"syn attack from {src_ip}")
                synTracker[src_ip]["time"] = 0
                synTracker[src_ip]["count"] = 0
                
            elif time.time() - synTracker[src_ip]["time"] >= 10:
                synTracker[src_ip]["time"] = 0
                synTracker[src_ip]["count"] = 0

        if src_ip not in tracker:
            tracker[src_ip] = set()
            print(src_ip)
        tracker[src_ip].add(ports)
        if len(tracker[src_ip])>10 and src_ip not in alerted :
            print(f"PORT SCAN DETECTED from {src_ip} {len(tracker[src_ip])} unique ports")
            logging.warning(f"PORT SCAN DETECTED from {src_ip} {len(tracker[src_ip])} unique ports")
            alerted.add(src_ip)

    


packets = sniff(prn=printSyn, iface='wld0')