import html
from shodan import Shodan
import time
import cefevent
import socket

def syslogsend(message):
    UDP_IP = "xxx.xxx.xxx.xxx" #<<=== here put destination IP for syslog
    UDP_PORT = 514
    MESSAGE = bytearray(message,"utf-8")
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

itemList = []
c = cefevent.CEFEvent()
api = Shodan('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx') #<<=== here put Shodan API key

for ip in range(1,254):
    time.sleep(3)
    try:
        host = api.host('xxx.xxx.xxx.'+str(ip)) #<<=== here put first 3 octets of public IP (designed for /24 subnet)
        for item in host['data']:
            itemDict= {}
            itemDict['deviceVendor'] = 'Shodan'
            itemDict['deviceProduct'] = 'Scanner'
            itemDict['name'] = 'Service detected'
            try: itemDict['dst'] = item['ip_str']
            except:itemDict['dst'] = "-"
            try: itemDict['dpt'] = item['port']
            except:itemDict['dpt'] = "-"
            try: itemDict['proto'] = item['transport']
            except:itemDict['proto'] = "-"
            itemDict['cs1Label'] = "shodanModule"
            itemDict['cs2Label'] = "httpTitle"
            itemDict['cs3Label'] = "expiredCert"
            itemDict['cs4Label'] = "certSn"
            try: itemDict['cs1'] = item['_shodan']['module']
            except:itemDict['cs1'] = "-"
            try: itemDict['cs2'] = html.unescape(item['http']['title'])
            except:itemDict['cs2'] = "-"
            try: itemDict['cs3'] = item['ssl']['cert']['expired']
            except:itemDict['cs3'] = "-"
            try: itemDict['cs4'] = '%x' % item['ssl']['cert']['serial']
            except:itemDict['cs4'] = "-"
            for key in itemDict:
                if itemDict[key] != "-":
                    c.set_field(key,itemDict[key])
            syslogsend(c.build_cef())
    except Exception as exc:
        print(exc)
