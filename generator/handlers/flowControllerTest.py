import os
import pickle
import time
from datetime import datetime
from subprocess  import Popen
from flows import FlowStats, Flow



def write_message(message, p):
    length = '{0:04d}'.format(len(message))
    p.write(b'X')
    p.write(length.encode('utf-8'))
    p.write(message)

def write(msg, p):
    length = '{0:04d}'.format(len(msg))
    os.write(p, b'X')
    os.write(p, length.encode('utf-8'))
    os.write(p, msg)

timeformat = "%Y-%m-%d %H:%M:%S.%f"

fa = datetime.strptime("2018-11-16 14:44:04.470770",
                       timeformat).strftime("%s.%f")
first_a = int(float(fa) * 1000)

pkt_a, arr_a = Flow.remove_empty_pkt([0, 0, 12, 0, 0, 0, 0],
                                     [0, 11, 5, 3, 2110, 0, 0])

print "{}, {}".format(pkt_a, arr_a)

fb = datetime.strptime("2018-11-16 14:44:04.476185",
                       timeformat).strftime("%s.%f")
first_b = int(float(fb) * 1000)

pkt_b, arr_b = Flow.remove_empty_pkt([0, 0, 40, 51, 61, 0, 0],
                                     [0, 14, 0, 2110, 0, 0, 0])
print "{}, {}".format(pkt_b, arr_b)


flowstat_client = FlowStats(pkt_a, arr_a, first_a, arr_b, first_b, pkt_b) 
flowstat_server = FlowStats(pkt_b, arr_b, first_b, arr_a, first_a, pkt_a)

client_pipe = "pipe_client"

server_pipe = "pipe_server"

if os.path.exists(client_pipe):
    os.remove(client_pipe)

if os.path.exists(server_pipe):
    os.remove(server_pipe)


server_proc = Popen(["python", "server.py", "--addr", "127.0.0.1",
                     "--port","8080", "--proto", "tcp", "--pipe", server_pipe])

time.sleep(1)
if os.path.exists(server_pipe):

    server_pipein = os.open(server_pipe, os.O_NONBLOCK|os.O_WRONLY)
    #ps = os.fdopen(server_pipein, 'wb')
    #write_message(pickle.dumps(flowstat_server), ps)
    write(pickle.dumps(flowstat_server), server_pipein)
    print "Writing Server stat"

client_proc = Popen(["python", "client.py", "--saddr", "127.0.0.3",
                     "--daddr","127.0.0.1", "--sport", "57980", "--dport",
                     "8080","--proto", "tcp","--pipe", client_pipe])

time.sleep(1) 
if os.path.exists(client_pipe):
    client_pipein = os.open(client_pipe, os.O_NONBLOCK|os.O_WRONLY)
    #pc = os.fdopen(client_pipein, 'wb')
    #write_message(pickle.dumps(flowstat_client), pc)
    write(pickle.dumps(flowstat_client), client_pipein)
    print "Writting Client stat"

client_proc.wait()
os.close(client_pipein)
print "Client done"
server_proc.wait()
os.close(server_pipein)
print "Server done"
