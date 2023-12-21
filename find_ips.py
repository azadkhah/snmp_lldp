import ipaddress
from pysnmp.hlapi import *
from pysnmp import hlapi
from threading import Thread
import traceback
from puresnmp.api.raw import get as raw_get
from puresnmp import get
from puresnmp import walk
import itertools
import json
import urllib.request
import socket
from icmplib import ping, multiping
import platform
from subprocess import Popen, PIPE
import re
import logging



oidfile='oids.json'
community='public'

global ips_enable
global ip_enable_SNMP
global oids
# global neighbor_ICMP
all_ip=[]
ip_enable_ICMP = []
ip_enable_SNMP = []
ips_enable = {}
# neighbor_ICMP={}
global node_inf_topology
node_inf_topology={}


def create_new_node(id):
    node_dict = {
        'ip': '',
        'name': '',
        'description':'',
        'icon':'',
        'user_id':'',
        'user_range':'',
        'version':'',
        'ICMP': False,
        'SNMP': False,
        'Arp': False,
        'SNMP_LLDP': False,
        'SNMP_CDP': False,
        'in_range': True,
        'neighbors':{}
    }
    node_inf_topology[id]=node_dict


def get_icon(node_des):
    icon=''
    if "Cisco IOS" in node_des:
        icon = 'switch'
    if "IOS XR" in node_des:
        print("change to router")
        icon = 'router'
    if "Cisco IOS Software [Amsterdam]" in node_des:
        icon = 'router'
    if "linux" in node_des:
        icon = 'host'
    if "Nexus" in node_des:
        icon = 'switch'
    if "DESKTOP" in node_des:
        icon = 'host'
    if "router" in node_des:
        icon = 'router'
    return icon

def create_new_neighbor(source_id,des_id):
    nei_dict = {
        'source_id': source_id,
        'des_id': des_id,
        'local_port':'',
        'remote_port':'',
        'ICMP_connection': False,
        'SNMP_Arp_connection': False,
        'SNMP_LLDP_connection': False,
        'SNMP_CDP_connection': False,
    }
    node_inf_topology[source_id]['neighbors'][des_id]=nei_dict


def ping_ip(target_ip,source_ip,user_id,user_range,version):
    logging.info("tracing: " + target_ip)
    route_list=[]
    c = 0
    count = 0
    p = None
    if "windows" in platform.platform().strip().lower():
        p = Popen(['tracert', target_ip], stdout=PIPE)
    elif "linux" in platform.platform().strip().lower():
        p = Popen(['traceroute', target_ip], stdout=PIPE)
    while True:
        line = p.stdout.readline()
        # print(line)
        if not line:
            # print("end")
            break
        if "Request timed out" in str(line.decode("utf-8")):
            # print("request time out")
            break
        if "Destination host unreachable" in str(line.decode("utf-8")):
            # print("Destination Host Unreachable")
            break
        fix_line = line.strip().decode("utf-8")
        ip = re.search(r'[0-9]+(?:\.[0-9]+){3}', fix_line)
        # print('result search',ip)
        if ip and len(ip.group().split(".")) == 4:
            c += 1
            # logging.info(ip.group())
            if c == 1 and target_ip == ip.group():
                # logging.info("first node or local router skipping: " + ip.group())
                continue
            count += 1
            route_list.append({"ip": ip.group(), "ttl": count})
            if ip.group().__eq__(target_ip):
                break
    if len(route_list)!=0:
        if not route_list[-1]["ip"].__eq__(target_ip):
            count += 1
            route_list.append({"ip": target_ip, "ttl": count})
    if len(route_list) == 0:
        pass
    elif len(route_list) == 1:
        if route_list[-1]["ip"] not in ips_enable:
            ips_enable[route_list[-1]["ip"]]={}
            ips_enable[route_list[-1]["ip"]]["ICMP"] = True
            id_new_node = str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(route_list[-1]["ip"]))
            ips_enable[route_list[-1]["ip"]]["id"] = id_new_node
            create_new_node(id_new_node)
            hostname =''
            icon=''
            try:
                hostname = socket.gethostbyaddr(route_list[-1]["ip"])[0]
                icon=get_icon(hostname)
            except:
                pass
            node_inf_topology[id_new_node]['ip'] = route_list[-1]["ip"]
            node_inf_topology[id_new_node]['user_range'] = user_range
            node_inf_topology[id_new_node]['user_id'] = user_id
            node_inf_topology[id_new_node]['version'] = version
            node_inf_topology[id_new_node]['name'] = hostname
            node_inf_topology[id_new_node]['icon'] = icon
            node_inf_topology[id_new_node]['ICMP'] = True
        else:
            ips_enable[route_list[-1]["ip"]]["ICMP"] = True
            id_old = ips_enable[route_list[-1]["ip"]]["id"]
            node_inf_topology[id_old]['ICMP'] = True
            # this_nei ={"ip":route_list[-1]["ip"]}
            # try:
            #     hostname = socket.gethostbyaddr(route_list[-1]["ip"])[0]
            #     this_nei["name"]=hostname
            # except:
            #     pass
            # neighbor_ICMP[source_ip]["neighbors"][route_list[-1]["ip"]]=this_nei
    else:
        if route_list[0]["ip"] not in ips_enable:
            ips_enable[route_list[0]["ip"]]={}
            ips_enable[route_list[0]["ip"]]["ICMP"] = True
            id_new_node = str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(route_list[0]["ip"]))
            ips_enable[route_list[0]["ip"]]["id"] = id_new_node
            create_new_node(id_new_node)
            hostname =''
            icon=''
            try:
                hostname = socket.gethostbyaddr(route_list[0]["ip"])[0]
                icon=get_icon(hostname)
            except:
                pass
            node_inf_topology[id_new_node]['ip'] = route_list[0]["ip"]
            node_inf_topology[id_new_node]['user_range'] = user_range
            node_inf_topology[id_new_node]['user_id'] = user_id
            node_inf_topology[id_new_node]['version'] = version
            node_inf_topology[id_new_node]['name'] = hostname
            node_inf_topology[id_new_node]['icon'] = icon
            node_inf_topology[id_new_node]['ICMP'] = True
        else:
            ips_enable[route_list[0]["ip"]]["ICMP"] = True
            id_old = ips_enable[route_list[0]["ip"]]["id"]
            node_inf_topology[id_old]['ICMP'] = True
        sorce_id=ips_enable[source_ip]["id"]
        target_id=ips_enable[route_list[0]["ip"]]["id"]
        create_new_neighbor(sorce_id,target_id)
        node_inf_topology[sorce_id]['neighbors'][target_id]['ICMP_connection']=True
        create_new_neighbor(target_id,sorce_id)
        node_inf_topology[target_id]['neighbors'][sorce_id]['ICMP_connection'] = True
        # this_nei = {"ip": route_list[0]["ip"]}
        # this_nei["name"] = 'n/a'
        # try:
        #     hostname = socket.gethostbyaddr(route_list[0]["ip"])[0]
        #     this_nei["name"] = hostname
        # except:
        #     pass
        # neighbor_ICMP[source_ip]["neighbors"][route_list[0]["ip"]]=this_nei
        for i in range(1,len(route_list)):
            if route_list[i]["ip"] not in ips_enable:
                ips_enable[route_list[i]["ip"]] = {}
                ips_enable[route_list[i]["ip"]]["ICMP"] = True
                id_new_node = str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(route_list[i]["ip"]))
                ips_enable[route_list[i]["ip"]]["id"] = id_new_node
                create_new_node(id_new_node)
                hostname = ''
                icon=''
                try:
                    hostname = socket.gethostbyaddr(route_list[i]["ip"])[0]
                    icon=get_icon(hostname)
                except:
                    pass
                node_inf_topology[id_new_node]['ip'] = route_list[i]["ip"]
                node_inf_topology[id_new_node]['user_range'] = user_range
                node_inf_topology[id_new_node]['user_id'] = user_id
                node_inf_topology[id_new_node]['version'] = version
                node_inf_topology[id_new_node]['name'] = hostname
                node_inf_topology[id_new_node]['icon'] = icon
                node_inf_topology[id_new_node]['ICMP'] = True
            else:
                ips_enable[route_list[i]["ip"]]["ICMP"] = True
                id_old = ips_enable[route_list[i]["ip"]]["id"]
                node_inf_topology[id_old]['ICMP'] = True
            sorce_id = ips_enable[route_list[i-1]["ip"]]["id"]
            target_id = ips_enable[route_list[i]["ip"]]["id"]
            create_new_neighbor(sorce_id, target_id)
            node_inf_topology[sorce_id]['neighbors'][target_id]['ICMP_connection'] = True
            create_new_neighbor(target_id, sorce_id)
            node_inf_topology[target_id]['neighbors'][sorce_id]['ICMP_connection'] = True
            # if route_list[i]["ip"] in neighbor_ICMP:
            #     if route_list[i-1]["ip"] not in neighbor_ICMP[route_list[i]["ip"]]["neighbors"]:
            #         this_nei={}
            #         this_nei["ip"]=route_list[i-1]["ip"]
            #         this_nei["name"]='n/a'
            #         try:
            #             hostname = socket.gethostbyaddr(route_list[i-1]["ip"])[0]
            #             this_nei["name"] = hostname
            #         except:
            #             pass
            #         neighbor_ICMP[route_list[i]["ip"]]["neighbors"][route_list[i-1]["ip"]]=this_nei
            # else:
            #     this_node={}
            #     this_node["ip"] = route_list[i]["ip"]
            #     this_node["name"] = 'n/a'
            #     try:
            #         hostname = socket.gethostbyaddr(route_list[i]["ip"])[0]
            #         this_node["name"] = hostname
            #     except:
            #         pass
            #     this_node['neighbors']={}
            #     this_nei = {"ip":route_list[i-1]["ip"]}
            #     this_nei["name"] = 'n/a'
            #     try:
            #         hostname = socket.gethostbyaddr(route_list[i-1]["ip"])[0]
            #         this_nei["name"] = hostname
            #     except:
            #         pass
            #     this_node['neighbors'][route_list[i-1]["ip"]]=this_nei
            #     neighbor_ICMP[route_list[i]["ip"]]=this_node
    print(target_ip,route_list)


def ips_ping(ip_list,user_id,user_range,version):
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    icon=get_icon(hostname)
    # neighbor_ICMP[IPAddr]={"ip":IPAddr,"name":hostname,"neighbors":{}}
    if IPAddr in ips_enable:
            id_new_node=ips_enable[IPAddr]['id']
            ips_enable[IPAddr]['ICMP']=True
            node_inf_topology[id_new_node]['ICMP']=True
    else:
        id_new_node = str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(IPAddr))
        ips_enable[IPAddr]={}
        ips_enable[IPAddr]['ICMP'] = True
        ips_enable[IPAddr]['id'] = id_new_node
        create_new_node(id_new_node)
        node_inf_topology[id_new_node]['ip'] = IPAddr
        node_inf_topology[id_new_node]['user_range'] = user_range
        node_inf_topology[id_new_node]['user_id'] = user_id
        node_inf_topology[id_new_node]['version'] = version
        node_inf_topology[id_new_node]['name'] = hostname
        node_inf_topology[id_new_node]['icon'] = icon
        node_inf_topology[id_new_node]['ICMP'] = True
    threads = []
    for ip in ip_list:
        if not ip==IPAddr:
            t = Thread(target=ping_ip, args=(ip,IPAddr,user_id,user_range,version,))
            threads.append(t)
            t.start()
    # wait for the threads to complete
    for t in threads:
        t.join()

def find_ip_subnet(ips):
   all_ips=[]
   for ip in ipaddress.IPv4Network(ips):
      all_ips.append(str(ip))
   return all_ips


def find_ip_range(start, end):
    '''Return IPs in IPv4 range, inclusive.'''
    start_int = int(ipaddress(start).packed.hex(), 16)
    end_int = int(ipaddress(end).packed.hex(), 16)
    return [ipaddress(ip).exploded for ip in range(start_int, end_int)]


def ips_enable_with_ICMP(ip_list):
    result = multiping(ip_list, privileged=False)
    for i in range(len(result)):
        if result[i].is_alive==True:
            ip_enable_ICMP.append(ip_list[i])


def valid_snmp(ip_snmp,user_id,user_range,version):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('public', mpModel=0),
        UdpTransportTarget((ip_snmp, 161)),
        ContextData(),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        pass

    elif errorStatus:
        pass

    else:
        ip_enable_SNMP.append(ip_snmp)
        name=''
        des=''
        icon=''
        try:
            name = str(get(ip_snmp, community, oids["standard"]["sysname"]), "utf-8")
            des = str(str(get(ip_snmp, community, oids["standard"]["sysdesc"]), "utf-8").split(',')[0])
            try:
                icon=get_icon(des)
            except Exception:
                traceback.print_exc()
        except Exception:
            traceback.print_exc()
        id_new_node=str(str(user_id)+":"+str(user_range)+":"+str(version)+":"+str(ip_snmp))
        create_new_node(id_new_node)
        global node_inf_topology
        node_inf_topology[id_new_node]['ip']=ip_snmp
        node_inf_topology[id_new_node]['user_range'] = user_range
        node_inf_topology[id_new_node]['user_id'] = user_id
        node_inf_topology[id_new_node]['version'] = version
        node_inf_topology[id_new_node]['name'] = name
        node_inf_topology[id_new_node]['icon'] = icon
        node_inf_topology[id_new_node]['description'] = des
        node_inf_topology[id_new_node]['SNMP'] = True
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
        if ip_snmp not in ips_enable:
            ips_enable[ip_snmp]={}
            ips_enable[ip_snmp]["id"]=id_new_node
            ips_enable[ip_snmp]["SNMP"] = True
        else:
            ips_enable[ip_snmp]["SNMP"] = True


def ips_enable_with_SNMP(ip_list,user_id,user_range,version):
    threads=[]
    for ip in ip_list:
          t = Thread(target=valid_snmp, args=(ip,user_id,user_range,version,))
          threads.append(t)
          t.start()
    # wait for the threads to complete
    for t in threads:
      t.join()


def find_SNMP_enable_getsubnet(ipwithsubnet='192.168.1.0/255.255.255.0'):
    try:
       all_ip =find_ip_subnet(ipwithsubnet)
       print(all_ip)
       ips_enable_with_SNMP(all_ip)
       print("ips:"+str(ip_enable_SNMP))
    except Exception:
        traceback.print_exc()
        print("cannot find ip address")
    return ip_enable_SNMP


def arp_nei(ip_temp,user_id,user_range,version):
    for record in ip_temp:
        try:
            for row in walk(record, community, oids["arp"]["ip"]):
                oid, value = row
                v=str(oid).split('.')
                ip_arp=str(str(v[-4])+'.'+str(v[-3])+'.'+str(v[-2])+'.'+str(v[-1]))
                print("neighbor arp:",ip_arp)
                if ip_arp in all_ip:
                    if ip_arp not in ips_enable:
                        ips_enable[ip_arp]={}
                        ips_enable[ip_arp]["Arp"] = True
                        id_new_node_arp = str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(ip_arp))
                        ips_enable[ip_arp]["id"] = id_new_node_arp
                        create_new_node(id_new_node_arp)
                        hostname =''
                        icon=''
                        try:
                            hostname = socket.gethostbyaddr(ip_arp)[0]
                            icon=get_icon(hostname)
                        except:
                            pass
                        node_inf_topology[id_new_node_arp]['ip'] = ip_arp
                        node_inf_topology[id_new_node_arp]['user_range'] = user_range
                        node_inf_topology[id_new_node_arp]['user_id'] = user_id
                        node_inf_topology[id_new_node_arp]['version'] = version
                        node_inf_topology[id_new_node_arp]['name'] = hostname
                        node_inf_topology[id_new_node_arp]['icon'] = icon
                        node_inf_topology[id_new_node_arp]['Arp'] = True
                    else:
                        ips_enable[ip_arp]["Arp"] = True
                        id_old_arp= ips_enable[ip_arp]["id"]
                        node_inf_topology[id_old_arp]["Arp"] = True
        except Exception:
            traceback.print_exc()

def lldp_nei(ip_temp,user_id,user_range,version):
    for record in ip_temp:
        try:
            local_ports = {}
            neighbour_names=[]
            neighbour_local_ports=[]
            neighbour_remote_ports=[]
            nei_des=[]
            icons_nei=[]
            for row in walk(record, community, oids["lldp"]["localport"]):
                oid, value = row
                i = int(str(oid).split('.')[-1])
                local_ports[i] = str(value, "utf-8")
            for row in walk(record, community, oids["lldp"]["remotesysname"]):
                oid, value = row
                neighbour_names.append(str(value,"utf-8"))
            for row in walk(record, community, oids["lldp"]["remoteif"]):
                oid, value = row
                i=int(str(oid).split('.')[-2])
                if len(local_ports) == 0:
                    neighbour_local_ports.append('')
                    neighbour_remote_ports.append(str(value, "utf-8"))
                else:
                    neighbour_local_ports.append(local_ports[i])
                    neighbour_remote_ports.append(str(value, "utf-8"))
            for row in walk(record, community, oids["lldp"]["remotesysdesc"]):
                oid, value = row
                nei_des.append(str(str(value,"utf-8").split(',')[0]))
                icons_nei.append(get_icon(nei_des[-1]))
            ids=[]
            for item in ips_enable:
                if ("SNMP" in ips_enable[item]) or ("LLDP" in ips_enable[item]) or("CDP" in ips_enable[item]):
                    ids.append(ips_enable[item]['id'])
            print("id that before snmp,lldp,",ids)
            for z in range(len(neighbour_names)):
                find=False
                id_found=''
                for id_old in ids:
                    if (node_inf_topology[id_old]['name']==neighbour_names[z]) and ((node_inf_topology[id_old]['description'] in nei_des[z]) or (nei_des[z] in node_inf_topology[id_old]['description'])):
                        id_found=id_old
                        find=True
                        print("I found",id_old)
                if find==True:
                    print("I found before", id_found)
                    sorce_id =ips_enable[record]['id']
                    target_id = id_found
                    node_inf_topology[sorce_id]['SNMP_LLDP']=True
                    node_inf_topology[target_id]['SNMP_LLDP']=True
                    ips_enable[node_inf_topology[target_id]["ip"]]["LLDP"]=True
                    ips_enable[record]["LLDP"]=True
                    if target_id in node_inf_topology[sorce_id]['neighbors']:
                        node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_LLDP_connection'] = True
                        if node_inf_topology[sorce_id]['neighbors'][target_id]['local_port']=='':
                            node_inf_topology[sorce_id]['neighbors'][target_id]['local_port']=neighbour_local_ports[z]
                        if node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port']=='':
                            node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port']=neighbour_remote_ports[z]
                    else:
                        create_new_neighbor(sorce_id, target_id)
                        node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_LLDP_connection'] = True
                        node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] = neighbour_local_ports[z]
                        node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] = neighbour_remote_ports[z]
                    if sorce_id in node_inf_topology[target_id]['neighbors']:
                        node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_LLDP_connection'] = True
                        if node_inf_topology[target_id]['neighbors'][sorce_id]['local_port']=='':
                            node_inf_topology[target_id]['neighbors'][sorce_id]['local_port']=neighbour_remote_ports[z]
                        if node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port']=='':
                            node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port']=neighbour_local_ports[z]
                    else:
                        create_new_neighbor(target_id, sorce_id)
                        node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_LLDP_connection'] = True
                        node_inf_topology[target_id]['neighbors'][sorce_id]['local_port']=neighbour_remote_ports[z]
                        node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] = neighbour_local_ports[z]
                else:
                    print("creat new node from lldp:",neighbour_names[z])
                    ip_new_lldp=str('unknown.'+ neighbour_names[z])
                    id_new_lldp= str(str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(ip_new_lldp))
                    create_new_node(id_new_lldp)
                    node_inf_topology[id_new_lldp]['ip'] = ip_new_lldp
                    node_inf_topology[id_new_lldp]['user_range'] = user_range
                    node_inf_topology[id_new_lldp]['user_id'] = user_id
                    node_inf_topology[id_new_lldp]['version'] = version
                    node_inf_topology[id_new_lldp]['name'] = neighbour_names[z]
                    node_inf_topology[id_new_lldp]['description'] = nei_des[z]
                    node_inf_topology[id_new_lldp]['icon'] = icons_nei[z]
                    sorce_id = ips_enable[record]['id']
                    target_id = id_new_lldp
                    node_inf_topology[sorce_id]['SNMP_LLDP'] = True
                    node_inf_topology[target_id]['SNMP_LLDP'] = True
                    ips_enable[ip_new_lldp]={}
                    ips_enable[ip_new_lldp]["id"]=id_new_lldp
                    ips_enable[ip_new_lldp]["LLDP"] = True
                    ips_enable[record]["LLDP"] = True
                    create_new_neighbor(sorce_id, target_id)
                    node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_LLDP_connection'] = True
                    node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] = neighbour_local_ports[z]
                    node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] = neighbour_remote_ports[z]
                    create_new_neighbor(target_id, sorce_id)
                    node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_LLDP_connection'] = True
                    node_inf_topology[target_id]['neighbors'][sorce_id]['local_port'] = neighbour_remote_ports[z]
                    node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] = neighbour_local_ports[z]

        except Exception:
            traceback.print_exc()


def cdp_nei(ip_temp, user_id, user_range, version):
    for record in ip_temp:
        try:
            local_ports = {}
            neighbour_names = []
            neighbour_local_ports = []
            neighbour_remote_ports = []
            nei_des = []
            icons_nei=[]
            for row in walk(record, community, oids["cdp"]["localport"]):
                oid, value = row
                i = int(str(oid).split('.')[-1])
                local_ports[i] = str(value, "utf-8")
            for row in walk(record, community, oids["cdp"]["remotesysname"]):
                oid, value = row
                neighbour_names.append(str(value, "utf-8"))
            for row in walk(record, community, oids["cdp"]["remoteif"]):
                oid, value = row
                i = int(str(oid).split('.')[-2])
                if len(local_ports) == 0:
                    neighbour_local_ports.append('')
                    neighbour_remote_ports.append(str(value, "utf-8"))
                else:
                    neighbour_local_ports.append(local_ports[i])
                    neighbour_remote_ports.append(str(value, "utf-8"))
            for row in walk(record, community, oids["cdp"]["remotesysdesc"]):
                oid, value = row
                nei_des.append(str(str(value, "utf-8").split(',')[0]))
                icons_nei.append(get_icon(nei_des[-1]))
            ids = []
            for item in ips_enable:
                if ("SNMP" in ips_enable[item]) or ("LLDP" in ips_enable[item]) or ("CDP" in ips_enable[item]):
                    ids.append(ips_enable[item]['id'])
            print("id that before snmp,lldp,", ids)
            for z in range(len(neighbour_names)):
                find = False
                id_found = ''
                for id_old in ids:
                    if (node_inf_topology[id_old]['name'] == neighbour_names[z]) and (
                            (node_inf_topology[id_old]['description'] in nei_des[z]) or (nei_des[z] in node_inf_topology[id_old]['description'])):
                        id_found = id_old
                        find = True
                        print("I found in cdp", id_old)
                if find == True:
                    print("I found before in cdp", id_found)
                    sorce_id = ips_enable[record]['id']
                    target_id = id_found
                    node_inf_topology[sorce_id]['SNMP_CDP'] = True
                    node_inf_topology[target_id]['SNMP_CDP'] = True
                    ips_enable[node_inf_topology[target_id]["ip"]]["CDP"] = True
                    ips_enable[record]["CDP"] = True
                    if target_id in node_inf_topology[sorce_id]['neighbors']:
                        node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_CDP_connection'] = True
                        if node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] == '':
                            node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] = neighbour_local_ports[z]
                        if node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] == '':
                            node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] = neighbour_remote_ports[
                                z]
                    else:
                        create_new_neighbor(sorce_id, target_id)
                        node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_CDP_connection'] = True
                        node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] = neighbour_local_ports[z]
                        node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] = neighbour_remote_ports[z]
                    if sorce_id in node_inf_topology[target_id]['neighbors']:
                        node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_CDP_connection'] = True
                        if node_inf_topology[target_id]['neighbors'][sorce_id]['local_port'] == '':
                            node_inf_topology[target_id]['neighbors'][sorce_id]['local_port'] = neighbour_remote_ports[
                                z]
                        if node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] == '':
                            node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] = neighbour_local_ports[
                                z]
                    else:
                        create_new_neighbor(target_id, sorce_id)
                        node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_CDP_connection'] = True
                        node_inf_topology[target_id]['neighbors'][sorce_id]['local_port'] = neighbour_remote_ports[z]
                        node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] = neighbour_local_ports[z]
                else:
                    print("creat new node from cdp:", neighbour_names[z])
                    ip_new_cdp = str('unknown.' + neighbour_names[z])
                    id_new_cdp = str(
                        str(user_id) + ":" + str(user_range) + ":" + str(version) + ":" + str(ip_new_cdp))
                    create_new_node(id_new_cdp)
                    node_inf_topology[id_new_cdp]['ip'] = ip_new_cdp
                    node_inf_topology[id_new_cdp]['user_range'] = user_range
                    node_inf_topology[id_new_cdp]['user_id'] = user_id
                    node_inf_topology[id_new_cdp]['version'] = version
                    node_inf_topology[id_new_cdp]['name'] = neighbour_names[z]
                    node_inf_topology[id_new_cdp]['description'] = nei_des[z]
                    node_inf_topology[id_new_cdp]['icon'] = icons_nei[z]
                    sorce_id = ips_enable[record]['id']
                    target_id = id_new_cdp
                    node_inf_topology[sorce_id]['SNMP_CDP'] = True
                    node_inf_topology[target_id]['SNMP_CDP'] = True
                    ips_enable[ip_new_cdp] = {}
                    ips_enable[ip_new_cdp]["id"] = id_new_cdp
                    ips_enable[ip_new_cdp]["CDP"] = True
                    ips_enable[record]["CDP"] = True
                    create_new_neighbor(sorce_id, target_id)
                    node_inf_topology[sorce_id]['neighbors'][target_id]['SNMP_CDP_connection'] = True
                    node_inf_topology[sorce_id]['neighbors'][target_id]['local_port'] = neighbour_local_ports[z]
                    node_inf_topology[sorce_id]['neighbors'][target_id]['remote_port'] = neighbour_remote_ports[z]
                    create_new_neighbor(target_id, sorce_id)
                    node_inf_topology[target_id]['neighbors'][sorce_id]['SNMP_CDP_connection'] = True
                    node_inf_topology[target_id]['neighbors'][sorce_id]['local_port'] = neighbour_remote_ports[z]
                    node_inf_topology[target_id]['neighbors'][sorce_id]['remote_port'] = neighbour_local_ports[z]

        except Exception:
            traceback.print_exc()


# def lldp_nei(ip_temp):
#     data = {}
#     for record in ip_temp:
#         try:
#             name = str(get(record, community, oids["standard"]["sysname"]),"utf-8")
#             des = str(get(record, community, oids["standard"]["sysdesc"]),"utf-8")
#             neighbour_names = []
#             neighbour_local_remote_ports=[]
#             nei_des=[]
#             neighbours = []
#             local_ports={}
#             for row in walk(record, community, oids["lldp"]["localport"]):
#                 oid, value = row
#                 i = int(str(oid).split('.')[-1])
#                 local_ports[i] = str(value, "utf-8")
#             for row in walk(record, community, oids["lldp"]["remotesysname"]):
#                 oid, value = row
#                 neighbour_names.append(('name', str(value,"utf-8")))
#             for row in walk(record, community, oids["lldp"]["remoteif"]):
#                 oid, value = row
#                 i=int(str(oid).split('.')[-2])
#                 if len(local_ports) == 0:
#                     neighbour_local_remote_ports.append(
#                         ('remote_port', str(value, "utf-8"), 'local_port', ''))
#                 else:
#                     neighbour_local_remote_ports.append(('remote_port', str(value,"utf-8"),'local_port',local_ports[i]))
#             for row in walk(record, community, oids["lldp"]["remotesysdesc"]):
#                 oid, value = row
#                 nei_des.append(('description', str(value,"utf-8")))
#             for a, b , c in itertools.zip_longest(
#                     neighbour_names,
#                     neighbour_local_remote_ports,
#                     nei_des,
#                     fillvalue='unknown'
#             ):
#                 neighbours.append({
#                     a[0]: a[1],
#                     b[0]: b[1],
#                     b[2]: b[3],
#                     c[0]: c[1]
#                 })
#             data[name] = {
#                 'ip': record,
#                 'description': des,
#                 'neighbors': neighbours
#             }
#         except Exception:
#             traceback.print_exc()
#     return data
#
#
# def cdp_nei(ip_temp,data):
#     for record in ip_temp:
#         try:
#             name = str(get(record, community, oids["standard"]["sysname"]),"utf-8")
#             des = str(get(record, community, oids["standard"]["sysdesc"]),"utf-8")
#             neighbour_names = []
#             neighbours = []
#             local_ports = {}
#             nei_des = []
#             neighbour_local_remote_ports=[]
#             for row in walk(record, community, oids["cdp"]["localport"]):
#                 oid, value = row
#                 i=int(str(oid).split('.')[-1])
#                 local_ports[i]=str(value,"utf-8")
#             for row in walk(record, community, oids["cdp"]["remotesysname"]):
#                 oid, value = row
#                 neighbour_names.append(('name', str(value,"utf-8")))
#             for row in walk(record, community, oids["cdp"]["remoteif"]):
#                 oid, value = row
#                 i = int(str(oid).split('.')[-2])
#                 if len(local_ports)==0:
#                     neighbour_local_remote_ports.append(
#                         ('remote_port', str(value, "utf-8"), 'local_port',''))
#                 else:
#                     neighbour_local_remote_ports.append(('remote_port', str(value, "utf-8"), 'local_port', local_ports[i]))
#             for row in walk(record, community, oids["cdp"]["remotesysdesc"]):
#                 oid, value = row
#                 nei_des.append(('description', str(value, "utf-8")))
#             for a, b, c in itertools.zip_longest(
#                     neighbour_names,
#                     neighbour_local_remote_ports,
#                     nei_des,
#                     fillvalue='unknown'
#             ):
#                 neighbours.append({
#                     a[0]: a[1],
#                     b[0]: b[1],
#                     b[2]: b[3],
#                     c[0]: c[1]
#                 })
#             data[name] = {
#                 'ip': record,
#                 'description': des,
#                 'neighbors': neighbours
#             }
#         except Exception:
#             traceback.print_exc()
#     return data

OUTPUT_TOPOLOGY_FILENAME = 'topology.js'
TOPOLOGY_FILE_HEAD = "\n\nvar topologyData = "


def write_topology_file(topology_json, header=TOPOLOGY_FILE_HEAD, dst=OUTPUT_TOPOLOGY_FILENAME):
    with open(dst, 'w') as topology_file:
        topology_file.write(header)
        topology_file.write(json.dumps(topology_json, indent=4, sort_keys=True))
        topology_file.write(';')

def generate_topology(data):
    topology_dict = {'nodes': [], 'links': []}
    for host in data:
        ip_host=data[host]['ip']
        name_host=data[host]['name']
        description_host=data[host]['description']
        icon_host=data[host]['icon']
        ICMP_host=data[host]['ICMP']
        SNMP_host=data[host]['SNMP']
        Arp_host=data[host]['Arp']
        SNMP_LLDP_host=data[host]['SNMP_LLDP']
        SNMP_CDP_host=data[host]['SNMP_CDP']
        topology_dict['nodes'].append({
            'id': host,
            'name':name_host,
            'primaryIP': ip_host,
            'icon': icon_host,
            'description': description_host,
            'ICMP': ICMP_host,
            'SNMP': SNMP_host,
            'Arp': Arp_host,
            'SNMP_LLDP': SNMP_LLDP_host,
            'SNMP_CDP': SNMP_CDP_host,
        })
        link_id = 0
        procced_node = []
        for host in data:
            procced_node.append(host)
            for nei_host in data[host]["neighbors"]:
                if nei_host not in procced_node:
                    topology_dict['links'].append({
                        'id': link_id,
                        'source': data[host]["neighbors"][nei_host]['source_id'],
                        'target': data[host]["neighbors"][nei_host]['des_id'],
                        'local_port': data[host]["neighbors"][nei_host]['local_port'],
                        'remote_port': data[host]["neighbors"][nei_host]['remote_port'],
                        'ICMP_connection': data[host]["neighbors"][nei_host]['ICMP_connection'],
                        'SNMP_Arp_connection': data[host]["neighbors"][nei_host]['SNMP_Arp_connection'],
                        'SNMP_LLDP_connection': data[host]["neighbors"][nei_host]['SNMP_LLDP_connection'],
                        'SNMP_CDP_connection': data[host]["neighbors"][nei_host]['SNMP_CDP_connection'],
                    })
                    link_id += 1
    return topology_dict

# def generate_topology(data):
#     topology_dict = {'nodes': [], 'links': []}
#     host_id = 0
#     host_id_map = {}
#     for host in data:
#         device_model = 'n/a'
#         device_serial = 'n/a'
#         device_ip = 'n/a'
#         host_id_map[host] = host_id
#         topology_dict['nodes'].append({
#             'id': host_id,
#             'name': host,
#             'primaryIP': device_ip,
#             'model': device_model,
#             'serial_number': device_serial
#         })
#         host_id += 1
#     for host in data:
#         for i in data[host]["neighbors"]:
#             if i["name"] not in host_id_map:
#                 host_id_map[i["name"]] = host_id
#                 device_model = 'n/a'
#                 device_serial = 'n/a'
#                 device_role = 'undefined'
#                 device_ip = 'n/a'
#                 topology_dict['nodes'].append({
#                     'id': host_id,
#                     'name': i["name"],
#                     'primaryIP': device_ip,
#                     'model': device_model,
#                     'serial_number': device_serial
#                 })
#                 host_id += 1
#
#     link_id = 0
#     procced_node=[]
#     for host in data:
#         procced_node.append(host)
#         for i in data[host]["neighbors"]:
#             if i["name"] not in procced_node:
#                 topology_dict['links'].append({
#                 'id': link_id,
#                 'source': host_id_map[host],
#                 'target': host_id_map[i["name"]]
#                 })
#                 link_id += 1
#     return topology_dict


def good_luck_have_fun(result):
    """Main script logic"""
    Toplogy=generate_topology(result)
    print(Toplogy)

    TOPOLOGY_DICT = {
            "links": [
                {
                    "id": 0,
                    "source": 0,
                    "target": 1,
                },
                {
                    "id": 1,
                    "source": 1,
                    "target": 0,
                }
            ],
            "nodes": [
                {
                    "icon": "router",
                    "id": 0,
                },
                {
                    "icon": "router",
                    "id": 1,
                }
            ]
    }
    write_topology_file(Toplogy)
    print('Open main.html in a project root with your browser to view the topology')


def connect(host='http://google.com'):
    try:
        urllib.request.urlopen(host) #Python 3.x
        return True
    except:
        return False


def ping_google(uid,range_user,version):
    if connect():
        ips_ping(['8.8.8.8'], uid, range_user, version)


if __name__ == '__main__':
    
    # uid="bdp"
    # range_user="192.168.1.0/255.255.255.0"
    # version=0
    # # Load OID data
    # with open(oidfile) as oidlist:
    #     oids = json.load(oidlist)
    #
    # all_ip = find_ip_subnet('192.168.1.0/255.255.255.0')
    # ips_enable_with_SNMP(all_ip,uid,range_user,version)
    # all_ip2 = find_ip_subnet('10.10.20.0/255.255.255.0')
    # ips_enable_with_SNMP(all_ip2,uid,range_user,version)
    #
    # # ip_temp = find_SNMP_enable_getsubnet('192.168.1.0/255.255.255.0')
    # arp_nei(ip_enable_SNMP,uid,range_user,version)
    # lldp_nei(ip_enable_SNMP,uid,range_user,version)
    # cdp_nei(ip_enable_SNMP,uid,range_user,version)
    #
    # ips_enable_with_ICMP(all_ip)
    # print("ips",ip_enable_ICMP)
    # ips_ping(ip_enable_ICMP,uid,range_user,version)
    # ping_google(uid,range_user,version)
    # # ip_temp = find_SNMP_enable_getsubnet('10.10.20.0/255.255.255.0')
    # # print(neighbor_ICMP)
    # # if '192.168.1.1' in neighbor_ICMP['192.168.1.17']['neighbors']:
    # #     print("hhhhhhhhhh")
    # # ips_ping(['192.168.1.14'])
    #
    # # uname = platform.uname()
    # # print(uname)
    # # print(f"System: {uname.system}")
    # # print(f"Node Name: {uname.node}")
    # # print(f"Release: {uname.release}")
    # # print(f"Version: {uname.version}")
    # # print(f"Machine: {uname.machine}")
    # # print(f"Processor: {uname.processor}")
    # # ip_temp=['10.10.20.172','10.10.20.173','10.10.20.174']
    # # all_data = lldp_nei(ip_temp)
    # # all_data={}
    # # all_data=cdp_nei(ip_temp,all_data)
    # # with open('node_inf_topology.json') as node_inf:
    # #     node_inf_topology = json.load(node_inf)
    # good_luck_have_fun(node_inf_topology)
    # #
    # # Serializing json
    # json_object = json.dumps(node_inf_topology, indent=4)
    #
    # # Writing to sample.json
    # with open("node_inf_topology.json", "w") as outfile:
    #     outfile.write(json_object)
