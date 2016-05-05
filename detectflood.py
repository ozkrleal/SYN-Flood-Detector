# Sniff TCP PACKETS
#   Oscar Leal
#   Luis Hernandez
#
#Networks 2
# It detects SYN FLOOD however it does not prevent it or close it
# to stop it. You HAVE to shell script:
	# iptables -A INPUT -m state --state NEW -p tcp -m tcp --syn
	#     -m recent --name synflood --set
	# iptables -A INPUT -m state --state NEW -p tcp -m tcp --syn
	#     -m recent --name synflood --update --seconds 1 --hitcount 60 -j DROP

from scapy.all import *

dictPackets = {} # {"0.0.0.0":1337}
dictSources = {}
#countPackages

def pkt_callback(pkt):
	#pkt.show()
	src = pkt.sprintf("%IP.src%")
	dst = pkt.sprintf("%IP.dst%")
	flags = pkt.sprintf("%TCP.flags%")

	#src is not needed to detect tho

	if flags == 'S':
		pkt_addtoDict(dst, src)
		#print pkt.summary()

#	if ("192.168" in dst)or("172.16" in dst)or("172.17" in dst)or
#		("172.18" in dst)or("172.19" in dst)or("172.2" in dst)or
#		("172.3" in dst)or(dst.startswith("10."):


def pkt_addtoDict(dst, src):
	if ("192.168" in dst)or(dst.startswith("10.")):
		if dst in dictPackets:#acum
			dictPackets[dst] += 1
			dictSources[dst] = src
		else:#add
			dictPackets[dst] = 1
			dictSources[dst] = src

	elif dst.startswith("172."):
		if dst in dictPackets:
			dictPackets[dst] += 1
			dictSources[dst] = src
		else:
			dictPackets[dst] = 1
			dictSources[dst] = src

	if dictPackets[dst] > 15:
		print("Possible SYN flooder!, cancel to watch details (Ctrl-C)")


def interp_dictionary():
	for syns in dictPackets:
		if dictPackets[syns] > 15:
			print("*"*30)
			print("PROBABLY A SYN FLOODER VICTIM: " + syns)
			print("COUNTER OF SYNS: " + str(dictPackets[syns]))
			print("SYN ATTACKER SOURCE: " + dictSources[syns])
			print("*"*30)
			print("PREVENT THIS BY introducing shell script in " + syns + " machine:")
			print("*iptables -A INPUT -m state --state NEW -p tcp -m tcp --syn ")
			print("*	-m recent --name synflood --set")
			print("*iptables -A INPUT -m state --state NEW -p tcp -m tcp --syn ")
			print("*	-m recent --name synflood --update --seconds 1 --hitcount 60 -j DROP")
	print("*"*30)
	print("Thanks for using SYN FLOOD DETECTOR.")
	print("*"*30)

#SYN FLAG
#flags = 'S'

sniff(iface="wlan0",
   prn=pkt_callback, filter="tcp", store=0)
#or
#sniff(prn=pkt_callback, filter="tcp", store=0)

interp_dictionary()
