#!/bin/env python

import sys
import enum
import time
import struct
import select
import socket

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
    # write packet
    buffer.extend(struct.pack( \
        "!2sHI", b"PK", packet_type.value, len(data) + 8))
    buffer.extend(data)

def now():
    return int(1000*time.time())

status = True

def get_status():
    global status
    return b"HIGH" if status else b"LOW"

def set_status():
    global status
    status = not status

    # the magic happens here
    print("STATUS CHANGED")

def main():
    # how often to send heartbeat packets in milliseconds
    HEARTBEAT_INTERVAL = 10000

    # how long does it take for the server to time out
    SERVER_TIMEOUT = 20000

    # minimum time to spend polling
    POLL_TIMEOUT = 100

    # client socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # socket file descriptor
    fd = s.fileno()

    # connect to server
    s.connect(("127.0.0.1", 1337))

    # allow non-blocking IO
    s.setblocking(0)

    # polling object
    poll = select.poll()

    # register socket 
    poll.register(fd, select.POLLIN | select.POLLOUT)

    # buffers
    recv_buf = bytearray()
    send_buf = bytearray()

    # heartbeat timestamps
    recv_heartbeat = now()
    send_heartbeat = now()

    try:
        while 1:
            # we're only polling a single file descriptor
            for _, mask in poll.poll(max( \
                HEARTBEAT_INTERVAL - now() + \
                    min(recv_heartbeat, send_heartbeat), POLL_TIMEOUT)):
                # socket error
                if mask & (select.POLLERR | select.POLLNVAL):
                    print("poll(): socket error", file=sys.stderr)
                    raise KeyboardInterrupt()

                # data in
                if mask & select.POLLIN:
                    # read from socket
                    data = s.recv(4096)

                    # POLLOUT with recv() < 1 means the socket
                    # is disconnected. (this is Linux specific,
                    # other *nixes set POLLHUP instead)
                    if len(data) < 1:
                        print("poll(): server closed the " \
                            "connection", file=sys.stderr)
                        raise KeyboardInterrupt()

                    # append to buffer
                    recv_buf += data
    
                    # attempt to read a packet
                    packet = packet_read(recv_buf)
                    if packet == None:
                        continue

                    if packet[0] == PacketType.HEARTBEAT:
                        recv_heartbeat = now()
                        print("Heartbeat from server (dt = {}ms)" \
                            .format(recv_heartbeat - send_heartbeat), \
                                file=sys.stderr)

                    # command packet
                    elif packet[0] == PacketType.COMMAND:
                        set_status()
                        status = b"OK"

                        print("Command from server, response '{}'" \
                            .format(str(status, "utf-8")))

                        # add POLLOUT back into the poll() eventmask
                        poll.modify(fd, select.POLLIN | select.POLLOUT)

                        # respond
                        packet_write(send_buf, PacketType.COMMAND, status)

                    # status packet
                    elif packet[0] == PacketType.STATUS:
                        status = get_status()

                        print("Status query from server, response '{}'" \
                            .format(str(status, "utf-8")))

                        # add POLLOUT back into the poll() eventmask
                        poll.modify(fd, select.POLLIN | select.POLLOUT)

                        # respond
                        packet_write(send_buf, PacketType.STATUS, status)

                # data out
                if mask & select.POLLOUT:
                    # write data to socket
                    i = min(len(send_buf), 4096)
                    if i > 0:
                        i = s.send(send_buf[:i])
                        del send_buf[:i]

                    # mask POLLOUT until there's more data
                    else:
                        poll.modify(fd, select.POLLIN)

            # send a new heartbeat packet
            if (now() - send_heartbeat) > HEARTBEAT_INTERVAL:
                # add POLLOUT back into the poll() eventmask
                poll.modify(fd, select.POLLIN | select.POLLOUT)

                # write the heartbeat packet into the send buffer
                packet_write(send_buf, PacketType.HEARTBEAT)
                send_heartbeat = now()

            # server timeout
            if (now() - recv_heartbeat) > SERVER_TIMEOUT:
                print("Server timed out", file=sys.stderr)
                raise KeyboardInterrupt()

    except KeyboardInterrupt:
        #import traceback
        #print(traceback.format_exc())
        pass

    # unregister socket
    poll.unregister(fd)

    try:
        # shutdown to inform server
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    # close socket
    s.close()

if __name__ == "__main__":
    sys.exit(main())
