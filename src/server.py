#!/bin/env python

import os
import sys
import enum
import time
import struct
import socket
import select
import ctypes
import threading

# types of packets sent between
# a node and the control server
class PacketType(enum.Enum):
    HEARTBEAT = 0 # keep connection alive
    COMMAND   = 1 # tell node to do something
    STATUS    = 2 # query node status

    @classmethod
    def has(self, value):
        return value in self._value2member_map_ 

def packet_read(buffer):
    # all packets have a 8 byte header
    # PK<type><size>
    if len(buffer) < 8:
        return None

    # unpack header
    tmp = struct.unpack("!2sHI", buffer[:8])

    # check magic number
    if tmp[0] != b"PK":
        del buffer[:2]
        return None

    # check packet type
    if not PacketType.has(tmp[1]):
        del buffer[:4]
        return None

    # check that the buffer is large
    # enough for us to read the packet
    if len(buffer) < tmp[2]:
        return None

    # return packet type and contents
    packet = (PacketType(tmp[1]), buffer[8:tmp[2]])

    # remove packet data
    del buffer[:tmp[2]]

    return packet

def packet_write(buffer, packet_type, data=b""):
    buffer += struct.pack( \
        "!2sHI", b"PK", packet_type.value, len(data) + 8)
    buffer += data

def now():
    return int(1000*time.time())

def line_read(buf):
    out = None

    i = 0
    while i < len(buf):
        if buf[i] == ord("\n"):
            out = bytes(buf[:i])
            del buf[:i+1]
            break
        i += 1

    return out

def main():
    # client timeout in milliseconds
    CLIENT_TIMEOUT = 20000

    # server socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # clients contexts, indexed by socket file descriptor
    clients = {}

    # allow address re-use
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # allow non-blocking IO
    s.setblocking(0)

    # listen on all interfaces, port 25565
    s.bind(("0.0.0.0", 25565))

    # polling object
    poll = select.poll()

    # register server socket and stdin
    poll.register(s.fileno(), select.POLLIN)
    poll.register(sys.stdin.fileno(), select.POLLIN)

    # start server
    s.listen()

    # line buffer for stdin
    line_buf = bytearray()

    # operation in progress
    in_progress = False

    # print menu on next IO loop
    print_menu = True

    # how many responses have been received (for status)
    responses = 0

    # menu state
    menu = 0

    # make the UI not break with messages
    last_line = ""
    def aware_print(msg):
        print("\r", end="")
        print(msg, flush=True)
        print(last_line, end="", flush=True)

    # allow the IO loop the be terminated by:
    # 1. CTRL+C (SIGTERM)
    # 2. CTRL+D (closing stdin)
    try:
        while not sys.stdin.closed:
            if print_menu:
                if menu == 0:
                    print("Remote node control:")
                    print("1) Node status")
                    print("2) Node control")
                    print("0) Exit")
                    last_line = "[0-2]: "
                    print(last_line, flush=True, end="")

                elif menu == 1:
                    print("Select node:")
                    i = 1
                    for fd in clients:
                        client = clients[fd]
                        print("{}) {}:{}".format(i, *client[1]))
                        i += 1
                    print("0) Back")
                    last_line = "[0-{}]: ".format(len(clients))
                    print(last_line, flush=True, end="")

                print_menu = False

            # perform IO
            for fd, mask in poll.poll(5000):
                # server socket
                if fd == s.fileno():
                    # socket error
                    if mask & (select.POLLERR | select.POLLNVAL):
                        print("poll() failed on server " \
                            "socket", file=sys.stderr)
                        raise KeyboardInterrupt()

                    # new client
                    elif mask & select.POLLIN:
                        c, addr = s.accept()
                        aware_print("New client ({}:{})".format(*addr))

                        # add client context
                        # (socket, address, in_buffer, out_buffer, heartbeat)
                        clients[c.fileno()] = [c, addr, bytearray(), \
                            bytearray(), now()]

                        # enable non-blocking IO
                        c.setblocking(0)

                        # register client file descriptor
                        poll.register(c.fileno(), \
                            select.POLLIN | select.POLLOUT)

                # stdin
                elif fd == sys.stdin.fileno():
                    # IO error (should be impossible)
                    if mask & (select.POLLERR | select.POLLNVAL):
                        print("poll() failed on stdin", file=sys.stderr)
                        raise KeyboardInterrupt()

                    # user input
                    elif mask & select.POLLIN:
                        # read character into line buffer
                        line_buf += os.read(fd, 1)

                        # attempt to read a line
                        line = line_read(line_buf)
                        if line == None:
                            continue

                        # discard uses input if operation is in progress
                        if in_progress:
                            continue
                       
                        # this spaghetti code is like this, because it's
                        # even more difficult to move the menu to it's
                        # own thread due to Pythons idiotic way of
                        # implementing threading

                        # main menu
                        if menu == 0:
                            try:
                                tmp = int(line)
                                if (tmp < 0) or (tmp > 2):
                                    raise ValueError()
                            except:
                                print("Invalid input, try again.")
                                print_menu = True
                                continue

                            # exit
                            if tmp == 0:
                                raise KeyboardInterrupt()

                            # query statuses
                            elif tmp == 1:
                                if len(clients) < 1:
                                    print("No clients connected.")
                                    print_menu = True
                                    continue

                                responses = 0
                                in_progress = True

                                for fd in clients:
                                    client = clients[fd]

                                    # add POLLOUT back into the poll() eventmask
                                    poll.modify(fd, select.POLLIN \
                                        | select.POLLOUT)

                                    # write packet
                                    packet_write(clients[fd][3], \
                                        PacketType.STATUS)

                            # enter submenu
                            elif tmp:
                                if len(clients) < 1:
                                    print("No clients connected.")
                                    menu = 0
                                    print_menu = True
                                    continue
                                    
                                menu = 1
                                print_menu = True

                        # device control submenu
                        elif menu == 1:
                            try:
                                tmp = int(line)
                                if (tmp < 0) or (tmp > len(clients)):
                                    raise ValueError()
                            except:
                                print("Invalid input, try again.")
                                print_menu = True
                                continue

                            # back to main menu
                            if tmp == 0:
                                menu = 0
                                print_menu = True
                                continue
                           
                            in_progress = True
                            responses = 0

                            fd = list(clients)[tmp - 1]
                            client = clients[fd]

                            # add POLLOUT back into the poll() eventmask
                            poll.modify(fd, select.POLLIN \
                                | select.POLLOUT)

                            # write packet
                            packet_write(client[3], \
                                PacketType.COMMAND)

                        # put user back into main menu
                        else:
                            menu = 0
                            print_menu = True

                # client socket
                else:
                    client = clients[fd]

                    # socket error
                    if mask & (select.POLLERR | select.POLLNVAL):
                        aware_print("Client socket error ({}:{}), " \
                            "dropping connection".format(*client[1]), \
                                file=sys.stderr)

                        # remove client
                        poll.unregister(fd)
                        client[0].shutdown(socket.SHUT_RDWR)
                        client[0].close()
                        del clients[fd]

                        continue

                    # data from client
                    if mask & select.POLLIN:
                        # read from socket
                        data = client[0].recv(4096)

                        # POLLOUT with recv() < 1 means the socket
                        # is disconnected. (this is Linux specific,
                        # other *nixes set POLLHUP instead)
                        if len(data) < 1:
                            aware_print("Client disconnected ({}:{})" \
                                .format(*client[1]))

                            # remove client
                            poll.unregister(fd)
                            client[0].shutdown(socket.SHUT_RDWR)
                            client[0].close()
                            del clients[fd]

                            continue

                        # append to buffer
                        client[2] += data

                        # attempt to read a packet
                        packet = packet_read(client[2])
                        if packet == None:
                            continue

                        # respond to heartbeat packet
                        if packet[0] == PacketType.HEARTBEAT:
                            #print("Heartbeat from client ({}:{})" \
                            #    .format(*client[1]), file=sys.stderr)

                            # add POLLOUT back into the poll() eventmask
                            poll.modify(fd, select.POLLIN | select.POLLOUT)

                            # write response packet
                            packet_write(client[3], PacketType.HEARTBEAT)
                            client[4] = now()

                        # command packet
                        elif packet[0] == PacketType.COMMAND:
                            responses += 1

                            print("Command, response from ({}:{}) '{}'" \
                                .format(*client[1], str(packet[1], "utf-8")))

                            if responses >= 1:
                                print_menu = True
                                in_progress = False

                        # status packet
                        elif packet[0] == PacketType.STATUS:
                            responses += 1

                            print("Status, response from ({}:{}) '{}'" \
                                .format(*client[1], str(packet[1], "utf-8")))

                            if responses >= len(clients):
                                print_menu = True
                                in_progress = False

                    # data to client
                    if mask & select.POLLOUT:
                        # write as much data as possible
                        i = min(len(client[3]), 4096)
                        if i > 0:
                            i = client[0].send(client[3][:i])
                            del client[3][:i]

                        # mask POLLOUT until there's more data
                        else:
                            poll.modify(fd, select.POLLIN)

            # scan through clients to determine
            # if any of them have timed out
            # (ie. we haven't received a HEARTBEAT packet in a while)
            for fd in list(clients):
                client = clients[fd]

                if (now() - client[4]) > CLIENT_TIMEOUT:
                    aware_print("Client timeout ({}:{}), dropping connection" \
                        .format(*client[1]))

                    fd = client[0].fileno()

                    # remove client
                    poll.unregister(fd)
                    client[0].shutdown(socket.SHUT_RDWR)
                    client[0].close()
                    del clients[fd]

    except KeyboardInterrupt:
        #import traceback
        #print(traceback.format_exc())
        pass

    # close connections to all clients
    for fd in list(clients):
        client = clients[fd]

        # close client socket
        client[0].shutdown(socket.SHUT_RDWR)
        client[0].close()

        # unregister file descriptor
        poll.unregister(fd)

        # remove client
        del clients[fd]

    # unregister server socket and stdin
    poll.unregister(s.fileno())
    poll.unregister(sys.stdin.fileno())

    # close server socket
    s.close()

    return 0

if __name__ == "__main__":
    sys.exit(main())
