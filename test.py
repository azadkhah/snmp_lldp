# from time import sleep, perf_counter
# from threading import Thread
#
#
# def task(id):
#     print(f'Starting the task {id}...')
#     sleep(1)
#     print(f'The task {id} completed')
#
#
# start_time = perf_counter()
#
# # create and start 10 threads
# threads = []
# for n in range(1, 11):
#     t = Thread(target=task, args=(n,))
#     threads.append(t)
#     t.start()
#
# # wait for the threads to complete
# for t in threads:
#     t.join()
#
# end_time = perf_counter()
#
# print(f'It took {end_time- start_time: 0.2f} second(s) to complete.')
from puresnmp import walk
from puresnmp import get
from puresnmp.api.raw import get as raw_get
# IP = '192.168.1.11'
# COMMUNITY ='public'
# OID = '1.3.6.1.2.1.31.1.1.1.1' # only an example
# # OID = '1.3.6.1.2.1.2.2.1.6' # only an example
# OID = '1.3.6.1.2.1.4.22.1' # only an example
# for row in walk(IP, COMMUNITY, OID):
#     oids, value =row
#     print(str(oids), ' : ', str(value))
from icmplib import ping

result = ping('192.168.1.51', count=2, interval=0.2, privileged=True)
output = {'icmp': result.is_alive}
print("ii",output)
# result = get(ip, community, oid)
# raw_result = raw_get(ip, community, oid)
# print(type(result), repr(result))
# # Output: <class 'ipaddress.IPv4Address'> IPv4Address('192.168.168.1')
# print(type(raw_result), repr(raw_result))
# # Output: <class 'puresnmp.types.IpAddress'> IpAddress(b'\xc0\xa8\xa8\x01')