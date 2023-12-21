import os
import json


OUTPUT_TOPOLOGY_FILENAME = 'topology.js'
TOPOLOGY_FILE_HEAD = "\n\nvar topologyData = "


def write_topology_file(topology_json, header=TOPOLOGY_FILE_HEAD, dst=OUTPUT_TOPOLOGY_FILENAME):
    with open(dst, 'w') as topology_file:
        topology_file.write(header)
        topology_file.write(json.dumps(topology_json, indent=4, sort_keys=True))
        topology_file.write(';')


def generate_topology(addr):
    topology_dict = {'nodes': [], 'links': []}
    f = open(addr)
    data = json.load(f)
    host_id = 0
    host_id_map = {}
    for host in data:
        device_model = 'n/a'
        device_serial = 'n/a'
        device_role = 'undefined'
        device_ip = 'n/a'
        if data.get(host):
            device_model = data[host].get('model', 'n/a')
            device_serial = data[host].get('serial_number', 'n/a')
            device_role = data[host].get('nr_role', 'undefined')
            device_ip = data[host].get('nr_ip', 'n/a')
        host_id_map[host] = host_id
        topology_dict['nodes'].append({
            'id': host_id,
            'name': host,
            'primaryIP': device_ip,
            'model': device_model,
            'serial_number': device_serial
        })
        host_id += 1
    for host in data:
        for i in data[host]["neighbors"]:
            if i["name"] not in host_id_map:
                host_id_map[i["name"]] = host_id
                device_model = 'n/a'
                device_serial = 'n/a'
                device_role = 'undefined'
                device_ip = 'n/a'
                topology_dict['nodes'].append({
                    'id': host_id,
                    'name': i["name"],
                    'primaryIP': device_ip,
                    'model': device_model,
                    'serial_number': device_serial
                })
                host_id += 1

    link_id = 0
    procced_node=[]
    for host in data:
        procced_node.append(host)
        for i in data[host]["neighbors"]:
            if i["name"] not in procced_node:
                topology_dict['links'].append({
                'id': link_id,
                'source': host_id_map[host],
                'target': host_id_map[i["name"]]
                })
                link_id += 1
    return topology_dict


def good_luck_have_fun():
    """Main script logic"""
    Toplogy=generate_topology("result.json")
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



if __name__ == '__main__':
    good_luck_have_fun()
