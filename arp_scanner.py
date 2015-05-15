#!/usr/bin/python
#arp scanner

from scapy.all import *
#need to find out the local subnet
ip='192.168.0.'
bmac='ff:ff:ff:ff:ff:ff'
def arpscanner():
    for lsb in range(1,256):
        #debugging
        ip2=ip+str(lsb)
       
        
        
        arprq=Ether(dst=bmac)/ARP(pdst=ip2,hwdst=bmac)
        arprp=srp1(arprq, timeout=.21,verbose=0,iface='wlan0')

        if arprp:
            print 'IP : + ' + arprp[0].psrc + ' MAC: ' + arprp[0].hwsrc

arpscanner()
