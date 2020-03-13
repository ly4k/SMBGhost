# Original code: https://github.com/ollypwn/SMBGhost/blob/master
#
# Updated by Knightmare/ 8balla / MinatoTW to support CID masks
# version 2.0 - free threading with every Happy Meal!
import socket
import struct
import sys
import threading
from netaddr import IPNetwork

# Packet to check vuln
pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

def checkvuln(ip):
     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     sock.settimeout(3)
     try :
        sock.connect(( str(ip),  445 ))
        sock.send(pkt)
     except:
        pass
        sock.close()
        return
     nb, = struct.unpack(">I", sock.recv(4))
     res = sock.recv(nb)
     sock.close()
     if not res[68:70] == b"\x11\x03":
       print('%s Not vulnerable' % ip)
     elif not res[70:72] == b"\x02\x00":
       print('%s Not vulnerable' % ip)
     else:
       print('%s Vulnerable!' % ip)
     sock.close()

if __name__ == "__main__":
  ## Check command line parameters are correct
  if len(sys.argv) != 2:
    print("Usage: python %s subnet" % (sys.argv[0]))
    sys.exit()
    ## run the function against all the IPs
  subnet = sys.argv[1]
  for ip in IPNetwork(subnet):
    threads = []
    # Make threads run in parallel
    runscan = threading.Thread(target=checkvuln, args=(ip,))
    threads.append(runscan)
    runscan.start()
  for runscan in threads:
    runscan.join()
