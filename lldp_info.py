from puresnmp import walk

import json

IP = "10.10.20.172"
COMMUNITY = 'public'
# OID = '1.3.6.1.2.1.14.10.1'
# OID = '1.0.8802.1.1.2.1.4.1.1.9'
# OID = '1.0.8802.1.1.2.1.3.3'
# OID = '1.0.8802.1.1.2.1.4.1.10'
# OID = '1.0.8802.1.1.2.1.4.1.1.8.0'
# OID = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'
# 3 or 4 or 5 the end is ip
# OID='1.0.8802.1.1.2.1.4.2.1.3'

# OID='1.0.8802.1.1.2.1.4.1.1.5'
# OID='1.0.8802.1.1.2.1'
# in 20 is ve
# "1.3.6.1.2.1.4.24"
OID='1.3.6.1.2.1.4.22.1'
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')
#
# s = b'\n\n\x14\xb2'
# s=b'RT\x00\x00S\xeb'
s=b'\x00\x00\x00\x01'


v = [ x for x in s ] # integer list
print( v )

lldp={}
import ast
for row in walk(IP, COMMUNITY, OID):
    oids, value =row
    lldp[str(oids)] = str(value)

    # if type(value)==int:
    #     lldp[str(oid)]=str(value)
    # else:
    #     print(value.decode(encoding='utf-32', errors='strict'))
    #     lldp[str(oid)] = str(value.decode(encoding='utf-16', errors='strict'))
# interface=[]
# OID = '.1.3.6.1.2.1.2.2.1.2'
# for row in walk(IP, COMMUNITY, OID):
#     oid, value =row
#     interface.append(str(value.decode(encoding='utf-8', errors='strict')))
# print(interface)
# print(discovery_output)
# Serializing json
json_object = json.dumps(lldp,indent=4)

# Writing to sample.json
with open("Arp_174.json", "w") as outfile:
    outfile.write(json_object)
import socket
ip=socket.gethostbyname('developer')
print(ip)