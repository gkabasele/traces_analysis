# echo_client.py

import socket
import sys
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-a", type=str, dest="ip", action="store", help="ip address of the host")
parser.add_argument("-p", type=int, dest="port", action="store", help="port of the service")
args = parser.parse_args()


port = args.port
ip = args.ip

data = " ".join(sys.argv[1:])
print 'data = %s' %data

# create a TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
        # connect to server 
        sock.connect((ip, port))

        # send data
        sock.sendall(bytes(data + "\n"))

        # receive data back from the server
        received = str(sock.recv(1024))
finally:
        # shut down
        sock.close()

        print("Sent:     {}".format(data))
        print("Received: {}".format(received))
