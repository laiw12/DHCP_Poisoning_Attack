from scapy.all import *
import sys
class sniffer():
    def dhcp_monitor(self,pkt):
        
        if pkt[DHCP].options[0][1]==1:
          print "DHCP Discover"
        if pkt[DHCP].options[0][1]==2:
          print "DHCP Offer"
        if pkt[DHCP].options[0][1]==3:
          print "DHCP Request"
        if pkt[DHCP].options[0][1]==4:
          print "DHCP Decline"
        if pkt[DHCP].options[0][1]==5:
          print "ACK Received"
        if pkt[DHCP].options[0][1]==6:
            print "NAK Received"
        if pkt[DHCP]:
            print "IP - src: "+str(pkt[IP].src)+"--> dst: " + str(pkt[IP].dst)
            print "MAC- src: "+str(pkt[Ether].src)+"--> dst: " + str(pkt[Ether].dst)
            

    def listen(self):
        sniff(filter="udp and (port 67 or port 68)",prn=self.dhcp_monitor,store=0)

    def start(self):
        # start packet listening thread
        thread = Thread(target=self.listen)
        thread.start()
        print "Starting DHCP Monitoring..."

if __name__=="__main__":
    snif = sniffer()
    snif.start()

    
