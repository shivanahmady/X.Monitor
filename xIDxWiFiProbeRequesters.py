import httplib
import json
import logging
import os
import re
import signal
import sys
import time
import unicodedata
import urllib

from netaddr import *
from scapy.all import *

ENCODING = 'utf-8'
VERSION = "0.0.0.0"
APPLICATION_NAME = "xIDxWiFiProbeRequester"
APPLICATION_UID = "7bd8eafc-53a7-11ea-8d77-2e728ce88125"
LOGGER_FILE_NAME = "_xIDx_LOGGER_7bd8eafc.log"
DATASET_FILE_NAME = "_DATASET_WifiProbeRequester.conf"

MAX_LENGTH = 20
MINUTE_LIST = []
FINGERPRINT_UID = []
_FINGERPRINT = ""
INTERFACE = ""
list = []
COLOR = ""
name = ""
pushoverenabled = False
UNIQUE_OUI = ""

###FUTURE IMPLEMENTATION
# if len(sys.argv) != 2:
#     print "Usage: arping2tex <net>\n  eg: arping2tex 192.168.1.0/24"

conf.verb=0
# ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=2)

# Set log level to benefit from Scapy warnings
# import logging
# logger = logging.getLogger("scapy")
# logger.setLevel(logging.INFO)
# logger.addHandler(logging.StreamHandler())

# from scapy.all import *

# class Test(Packet):
#     name = "Test packet"
#     fields_desc = [ ShortField("test1", 1),
#                     ShortField("test2", 2) ]

# def make_test(x,y):
#     return Ether()/IP()/Test(test1=x,test2=y)

# if __name__ == "__main__":
#     interact(mydict=globals(), mybanner="Test add-on v3.14")


reload(sys)
sys.setdefaultencoding('utf-8')
def VALIDATE_CONFIGURATION():
		if not os.path.isfile(DATASET_FILE_NAME):
			print ("\n\033[91m\033[1m[+]\033[0m ERROR ERROR -------CONFIGURATION FILE NOT FOUND----------\033[0m\n")
			file = open(DATASET_FILE_NAME, "w")
			file.close()
			print ("\033[93m\033[1m[+]\033[0m CONFIG: \033[94m\033[1m[" + DATASET_FILE_NAME + "]\033[0m\n")
			exit()
		else:
			try:
				with open(DATASET_FILE_NAME,'rU') as f: list.append(json.load(f))
				global INTERFACE
				INTERFACE = str(list[0]['config'][0]['interface'])
			except:
				print ("\033[91m ERROR CONFIG FILE.")
				print ("Edit "+DATASET_FILE_NAME+" and try again.\033[0m\n\n")
				exit()
		global pushoverenabled
		if str(list[0]['config'][1]['pushoverapitoken']) != "":
					pushoverenabled = "Enabled"
		else:
					pushoverenabled = "Disabled"


def xLAUNCH():
     logo = "AAAaaaa"

def VIEW_NOW() :
		print ("\n\033[92m\033[1m[+]\033[0m CURRENTLY:")
		print ("    # :        MAC        -    NAME")
		for i in range(len(list[0]['list'])) :
			COLOR = '\033[9'+list[0]['list'][i]['color']+'m'
			print ("    "+str(i)+" : " + COLOR + list[0]['list'][i]['mac']+ " - " + list[0]['list'][i]['name'] + '\033[0m')
			print ("\n\033[92m\033[1m[+]\033[0m Configuration:")
			timea = time.strftime("%Y-%m-%d %H:%M") + "]\033[0m"
			print ("    Current Time            \033[94m\033[1m[" + timea)
			print ("    Configuration File      \033[94m\033[1m[" + DATASET_FILE_NAME + "]\033[0m")
			print ("    Log File                \033[94m\033[1m[" + LOGGER_FILE_NAME + "]\033[0m")
			print ("    Monitor Interface       \033[94m\033[1m[" + INTERFACE + "]\033[0m")
			print ("    Push Alert  \033[94m\033[1m[" + pushoverenabled + "]\033[0m\n")
			print ("\n\033[92m\033[1m[+]\033[0m Listening for probe requests...\n")

def GetUNIQUE_OUI(pkt) :
		global UNIQUE_OUI
		try :
			UNIQUE_OUI = UNIQUE_OUI(pkt.addr2.replace(":","").upper()[0:6])
			UNIQUE_OUI = UNIQUE_OUI.registration().org
		except :
			UNIQUE_OUI = "(Unknown)"

def SearchList(pkt):
		global COLOR
		global name
		name = "NA"
		COLOR = ""
		if pkt.info == "" : pkt.info = "(Hidden)"
		for i in range(len(list[0]['list'])) :
			if pkt.addr2 == list[0]['list'][i]['mac'] :
				name = list[0]['list'][i]['name']
				COLOR = '\033[9'+list[0]['list'][i]['color']+'m'

def PacketHandler(pkt) :
		if pkt.haslayer(Dot11ProbeReq) :
			GetUNIQUE_OUI(pkt)
			SearchList(pkt)
			status(pkt)
			WriteLog(_FINGERPRINT)

def SIG_HANDLER(signal, frame):
		print ("\n\033[92m\033[1m[+]\033[0m EXIT\n")
		sys.exit(0)

def PUSH_ALERT(__FINGERPRINT):
		conn = httplib.HTTPSConnection("api.pushover.net:443")
		conn.request("POST", "/1/messages.json",
		urllib.urlencode({
		"token": str(list[0]['config'][1]['pushoverapitoken']),
		"user": str(list[0]['config'][2]['pushoveruserkey']),
			"message": _FINGERPRINT,
		}), { "Content-type": "application/x-www-form-urlencoded" })
		conn.getresponse()

def status(pkt) :
		global _FINGERPRINT
		timea = time.strftime("%Y-%m-%d %H:%M")
		namef = " NAME: " + name.ljust(MAX_LENGTH)[0:MAX_LENGTH]
		mac = " MAC: " + pkt.addr2
		SSID = " SSID: " + pkt.info.ljust(MAX_LENGTH)[0:MAX_LENGTH]
		UNIQUE_OUI = " UNIQUE_OUI: "+ UNIQUE_OUI
		db = -(256-ord(pkt.notdecoded[-4:-3]))

		if db <= -100: 
			quality = 0
		elif db >= -50: 
			quality = 100
		else: 
			quality = 2 * (db + 100)

		quality = str(quality)+"%"
		quality = " SIGNAL: " + quality.ljust(4, ' ')

		_FINGERPRINT = COLOR + timea + quality + namef + mac + SSID + UNIQUE_OUI +'\033[0m'

		if _FINGERPRINT not in FINGERPRINT_UID :
    			FINGERPRINT_UID.append(_FINGERPRINT)
		print ("_FINGERPRINT" + _FINGERPRINT)
		if COLOR == '\033[9'+'1'+'m' :
    			PUSH_ALERT(_FINGERPRINT[22:-3])

def WriteLog(_FINGERPRINT):
			file = open(LOGGER_FILE_NAME, "a")
			file.write(_FINGERPRINT + "\n")
			file.close()

def arp_monitor_callback(pkt):
    	if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
			return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")

xLAUNCH()
sniff(prn=arp_monitor_callback, filter="arp", store=0)
VALIDATE_CONFIGURATION()
VIEW_NOW()
signal.signal(signal.SIGINT, SIG_HANDLER)
sniff(iface=INTERFACE, prn = PacketHandler, store=0)
signal.pause()