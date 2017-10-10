#!/usr/bin/python3

import socket


if __name__ == "__main__":

   sckt_encap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
   sckt_encap.bind(("vnet10", 0))

   while True:

      frame, source = sckt_encap.recvfrom(65565)
      print(str(frame))


