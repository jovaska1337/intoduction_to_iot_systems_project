#!/bin/env python

import os
import sys
import time
import enum
import dbus
import fcntl
import select
import struct
import socket
import atexit
import signal
import random
import subprocess
import lxml.etree
import http.client

# currently NETLINK and NONLINK are functionally equivalent
# as we're not using the extra modems for load-balancing or
# replacing the a GATEWAY node if it drops from the mesh
class Mode(enum.Enum):
    GATEWAY = 0 # master node of the network
    NETLINK = 1 # node with a modem but not a master
    NONLINK = 2 # node without a modem

def now():
    return int(1000*time.time())

def parse_cmdline(cmdline):
    out = []
    
    i = 0
    j = 0
    q = True
    h = False
    s = False

    # parse into an array
    while i < len(cmdline):
        c = cmdline[i]

        # spaces delimit parameters unless quoted
        if c == " ":
            if q and s:
                tmp = cmdline[j:i].strip()

                if h:
                    tmp = tmp[1:-1]
                out.append(tmp)

                j = i
                s = False
                h = False

        # quote delimited parameter
        elif c == "\"":
            h = True
            q = not q

        # non-space character
        else:
            s = True

        # last iteration as the end of string
        # also delimits a paramater
        if (i == (len(cmdline) - 1)) and q and s:
            tmp = cmdline[j:].strip()
            if h:
                tmp = tmp[1:-1]
            out.append(tmp)

        i += 1

    return out

# run a command without input/output streams
def cmd(cmdline):
    cmd = parse_cmdline(cmdline)

    # empty command line
    if len(cmd) < 1:
        return True

    # call command in subprocess
    try:
        proc = subprocess.Popen(cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        proc.wait()

    # we don't allow exceptions from the
    # subprocess module to bubble
    except:
        return True

    # return based on exit status (0 = success) we return
    # True on failure to make error handling easier
    return proc.returncode != 0

# run a command line as a child process (ie. we start the
# program and return the PID so the parent can call os.wait()
# and terminate the child via a signal later)
def run_child(cmdline):
    cmd = parse_cmdline(cmdline)

    # empty command line
    if len(cmd) < 1:
        return -1

    # use the fork() syscall to create a child process
    pid = os.fork()

    # child gets pid == 0
    if pid == 0:
        # redirect standard IO to /dev/null
        fd = os.open("/dev/null", os.O_RDWR)
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)

        # replace process image
        os.execvp(cmd[0], cmd)

    return pid

# create B.A.T.M.A.N. interface and load kernel module
# returns (bat_iface, net_iface, error)
def bat_init(bat_iface):
    # search for a wireless interface
    try:
        for net_iface in os.listdir("/sys/class/net"):
            # wireless interfaces always begin with 'wl'
            if net_iface.startswith("wl"):
                break

        # no wireless interfaces
        else:
            return (bat_iface, None, True)

    # /sys/class/net doesn't exist (impossible on
    # a system with networking support)
    except:
        return (bat_iface, None, True)

    # this isn't essential but yields better performance
    # as B.A.T.M.A.N. packets won't fragment on the link layer
    cmd("ip link set down dev {}".format(net_iface))
    cmd("ip link set mtu 1560 dev {}".format(net_iface))

    # run init commands
    # we have to run B.A.T.M.A.N. over IBSS as none of the
    # network hardware I have supports IEEE802.11s (mesh_point
    # interface mode) on Linux (we could probably use the
    # iwlwifi-next driver but it's not available no Fedora at
    # the moment) I we had proper hardware, the mesh configuration
    # doesn't require an SSID
    if cmd("modprobe batman-adv") \
        or cmd("batctl -m {} interface create".format(bat_iface)) \
        or cmd("batctl -m {} interface add -M {}" \
            .format(bat_iface, net_iface)) \
        or cmd("rfkill unblock wlan") \
        or cmd("ip link set up dev {}".format(net_iface)) \
        or cmd("iw dev {} set type ibss".format(net_iface)) \
        or cmd("iw dev {} ibss join ibss-mesh-cell 2412".format(net_iface)) \
        or cmd("ip link set up dev {}".format(bat_iface)):
        return (bat_iface, net_iface, True)

    return (bat_iface, net_iface, False)

# remove B.A.T.M.A.N. interface and unload kernel module
def bat_clean(bat_iface, net_iface):
    # it doesn't really matter if any of these fail
    # because there's really nothing we can do about it
    
    # net_iface can be None
    if net_iface:
        cmd("iw {} ibss leave".format(net_iface))
        cmd("iw {} set type managed".format(net_iface))
        cmd("ip link set down dev {}".format(net_iface))
        cmd("batctl -m {} interface del -M {}" \
            .format(bat_iface, net_iface))
    cmd("batctl -m {} interface destroy".format(bat_iface))
    cmd("modprobe -r batman-adv")

# activate modem
# returns (modem_index, sim_index, network_interface, dhclient_pid, error)
def modem_init(subnet_iface):
    # we could use the ModemManager dbus interface
    # to perform all the configuration but using
    # mmcli subprocess calls is A LOT simpler

    # these need to have known values at the start
    modem = None
    sim = None
    net_iface = None
    dhclient_pid = None
    dhclient_cfg = "/tmp/dhclient_modem.conf"
    dhclient_lea = "/tmp/dhclient_modem.leases"

    try:    
        # list available modems through the ModemManager dbus interface
        bus = dbus.SystemBus()
        mod = bus.get_object("org.freedesktop.ModemManager1",
            "/org/freedesktop/ModemManager1/Modem")

        # locate first modem
        tmp = bus.get_object(
            "org.freedesktop.ModemManager1",
            "/org/freedesktop/ModemManager1/Modem")

        # list all child nodes with the dbus introspection interface
        xml = tmp.Introspect(
            dbus_interface="org.freedesktop.DBus.Introspectable")

        # parse the introspection XML output
        root = lxml.etree.XML(xml, lxml.etree.XMLParser())

        # iterate child nodes (modem)
        for child in root:
            # select first modem
            if "name" in child.attrib:
                modem = child.attrib["name"]
                break

        # no modems
        else:
            return (None, None, None, None, None, True)

        # locate first sim of the modem
        tmp = bus.get_object(
            "org.freedesktop.ModemManager1",
            "/org/freedesktop/ModemManager1/Modem/{}".format(modem))
        sim = tmp.Get(
            "org.freedesktop.ModemManager1.Modem",
            "Sim", dbus_interface="org.freedesktop.DBus.Properties") \
            .split("/")[-1]

        # find the network interface corresponding to the modem
        for name, _type in tmp.Get( \
            "org.freedesktop.ModemManager1.Modem", "Ports", \
                dbus_interface="org.freedesktop.DBus.Properties"):
            # _type == 2 means a network interface
            if _type == 2:
                net_iface = name
                break

        # this shouldn't be possible to reach
        else:
            return (modem, sim, None, None, None, True)

    # the only way we should get an exception here is if
    # the ModemManager dbus interface doesn't exist
    except:
        return (modem, sim, net_iface, None, None, True)

    # init commands:
    # 1. unlock sim
    # 2. activate modem
    # 3. put the interface up
    if cmd("mmcli --sim={} --pin={}".format(sim, "0000")) \
        or cmd("mmcli --modem={} --simple-connect apn=internet".format(modem)) \
        or cmd("ip link set up dev {}".format(net_iface)): \
        return (modem, sim, net_iface, None, None, True)

    # write config (as the full feature set
    # can not be configured via command line)
    try:
        with open(dhclient_cfg, "w") as fp:
            # lower the default timeout (60 seconds)
            fp.write("timeout 10;\n")
    except:
        return (modem, sim, net_iface, None, None, True)

    # now we need to use a DHCP client for
    # IP address autoconfiguration
    dhclient_pid = run_child("dhclient -d -4 --no-pid -cf \"{}\" " \
        "-lf \"{}\" --no-pid -sf /usr/sbin/dhclient-script -pf /dev/null {}" \
        .format(dhclient_cfg, dhclient_lea, net_iface))

    # check that dhclient doesn't immediately terminate
    try:
        # this raises an OSError if the PID is invalid
        time.sleep(5)
        os.kill(dhclient_pid, 0)
    except:
        return (modem, sim, net_iface, None, \
            [dhclient_cfg, dhclient_lea], True)

    # allow IP forwarding + NAT to the modem interface
    if cmd("sysctl net.ipv4.ip_forward=1") \
        or cmd("iptables --flush") \
        or cmd("iptables -t nat -A POSTROUTING -o {} " \
            "-j MASQUERADE".format(net_iface)) \
        or cmd("iptables -A INPUT -i {} -j ACCEPT".format(subnet_iface)) \
        or cmd("iptables -A INPUT -i {} -m state --state " \
            "ESTABLISHED,RELATED -j ACCEPT".format(net_iface)) \
        or cmd("iptables -A OUTPUT -j ACCEPT"): \
        return (modem, sim, net_iface, dhclient_pid, \
            [dhclient_cfg, dhclient_lea], True)

    return (modem, sim, net_iface, dhclient_pid, \
        [dhclient_cfg, dhclient_lea], False)

# deactivate modem
def modem_clean(modem, sim, net_iface, dhclient_pid, files):
    # terminate dhcp client
    if dhclient_pid != None:
        try:
            print("Terminating dhclient (modem)", file=sys.stderr)
            os.kill(dhclient_pid, signal.SIGTERM)
            os.waitpid(dhclient_pid, 0)
        except:
            pass

    # bring interface down
    if net_iface != None:
        cmd("ip link set down dev {}".format(net_iface))

    # reset modem
    if modem != None:
        cmd("mmcli --modem={} --reset".format(modem))

    # remove routing configuration
    cmd("sysctl net.ipv4.ip_forward=0")
    cmd("iptables --flush")

    # remove temporary files
    if files:
        for file in files:
            try:
                os.remove(file)
            except:
                pass

# convert integer representation
# of an IP address to a string
def int_to_addr(i):
    return str((i >> 24) & 0xFF) \
        + "." + str((i >> 16) & 0xFF) \
        + "." + str((i >> 8) & 0xFF) \
        + "." + str(i & 0xFF)

# compute IP header checksum
def ip_checksum(msg):
    out = 0

    i = 0
    j = len(msg)
    while j > 1:
        out += struct.unpack("!H", msg[i:i+2])[0]

        i += 2
        j -= 2

    if j > 0:
        out += msg[i]

    out = (out >> 16) + (out & 0xFFFF)
    out += (out >> 16)

    return (~out) & 0xFFFF

# detect DHCP servers accessible from a network interface
def dhcp_detect(net_iface, timeout):
    # we have to implement this with a raw socket writing all the
    # protocol headers ourselves, as it's the only way we're able
    # to receive DHCPOFFER responses when the interface has no
    # valid IP address. (the Linux protocol stack drops the
    # response packets if we use a UDP socket)

    # found unique servers are stored here
    servers = []

    # create a raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))

    # get interface MAC address
    mac = fcntl.ioctl(s, 0x8927, \
        struct.pack("256s", bytes(net_iface, "utf-8")))[18:24]

    # bind to interface
    s.bind((net_iface, 0))

    buf = bytearray()

    # ethernet frame
    buf += b"\xFF\xFF\xFF\xFF\xFF\xFF"
    buf += mac
    buf += struct.pack("!H", 0x800)

    eth_end = len(buf)

    # IP header
    buf += struct.pack("B", 5 | (4 << 4)) # version + header length
    buf += struct.pack("B", 0)            # DSCP + ECN
    buf += struct.pack("!H", 0)           # total size
    buf += struct.pack("!H", 0)           # id
    buf += struct.pack("!H", 0)           # flags + fragment offset
    buf += struct.pack("B", 255)          # time to live
    buf += struct.pack("B", 17)           # protocol (UDP)
    buf += struct.pack("!H", 0)           # checksum
    buf += struct.pack("!I", 0)           # source address
    buf += struct.pack("!I", 0xFFFFFFFF)  # destination address

    ip4_end = len(buf)

    # UDP header
    buf += struct.pack("!H", 68) # source port
    buf += struct.pack("!H", 67) # destination port
    buf += struct.pack("!H", 0)  # size
    buf += struct.pack("!H", 0)  # checksum (not computed)

    udp_end = len(buf)

    xid = random.randint(0, 0xFFFFFFFF) 

    # DHCPDISCOVER packet
    packet = struct.pack("!BBBBIHHIIII16s64s128s312s",
        1, # packet type (1 == BOOTREQUEST)
        1, # hardware address (1 == ETHERNET)
        6, # hw address length (6 for ETHERNET)
        0, # no. hops
        xid, # transaction id
        0xFF, # seconds (timing)
        32768, # flags (32768 = DHCP_BROADCAST_FLAG)
        0, # IPv4 address (this machine)
        0, # IPv4 address (server offer)
        0, # IPv4 address (server)
        0, # IPv4 address (relay)
        mac, # hardware address (this machine)

        # server name
        b"\0",

        # boot file name (for BOOTP)
        b"\0",

        # options
        b"\x63\x82\x53\x63"  # magic cookie
        b"\x35\x01\x01"      # (TYPE, LEN, DHCPDISCOVER)
    )

    # add packet
    buf += packet

    # update size fields 
    buf[ip4_end-18:ip4_end-16] = struct.pack("!H", len(buf) - eth_end)
    buf[udp_end-4:udp_end-2] = struct.pack("!H", len(buf) - ip4_end)

    # IP header checksum
    buf[ip4_end-10:ip4_end-8] = struct.pack("!H", \
        ip_checksum(buf[eth_end:ip4_end]))

    # send frame
    s.send(buf)
    
    # attempt to receive a DHCPOFFER
    t_2 = now()
    while 1:
        t_1 = now()

        # time delta
        delta = t_1 - t_2

        # timeout expired
        if delta > timeout:
            break

        # read a single ethernet frame
        try:
            s.settimeout(timeout - delta)
            data = s.recv(2048)
        except socket.timeout:
            break

        # calculate IP header size
        iph_size = 4 * (data[14] & 0x0F)
        iph_end = iph_size + 14

        # ethernet frame
        eth = struct.unpack("!6s6sH", buf[:14])

        # make sure destination is our interface
        # (this returns invalid MAC addresses for whatever reason)
        #if eth[0] != mac:
        #    continue

        # IP header
        iph = struct.unpack("!BBHHHBBHII{}s" \
            .format(iph_size - 20), data[14:iph_end])

        # protocol needs to be UDP, destination
        # address needs to be 0xFFFFFFFF (broadcast)
        if (iph[6] != 17) or (iph[9] != 0xFFFFFFFF):
            continue

        udp_end = iph_end + 8

        # UDP header
        udp = struct.unpack("!HHHH", data[iph_end:udp_end])

        # destination port needs to be 68
        if udp[1] != 68:
            continue

        tmp = data[udp_end:udp_end+udp[2]-8]
        
        # unpack as DHCP packet
        packet = struct.unpack("!BBBBIHHIIII16s64s128s{}s" \
            .format(len(tmp) - 236), tmp)

        # for this to be a DHCPOFFER
        # 1. op == 2
        # 2. magic cookie is valid
        # 3. hardware address matches
        if (packet[0] != 2) or (not \
            packet[14].startswith(b"\x63\x82\x53\x63")) \
            or (not packet[11].startswith(mac)):
            continue

        # find server address
        server = packet[9]
        if server == 0:
            # if the server doesn't send it's address
            # use the source address in the IP header
            server = iph[8]

        server = int_to_addr(server)

        print("OFFER {} FROM {}".format( \
            int_to_addr(packet[8]), server), file=sys.stderr)

        if not server in servers:
            servers.append(server)

        t_2 = now()

    s.close()

    return servers

def dhcp_client_init(net_iface):
    dhclient_pid = None
    dhclient_cfg = "/tmp/dhclient_mesh.conf"
    dhclient_lea = "/tmp/dhclient_mesh.leases"

    # write config (as the full feature set
    # can not be configured via command line)
    try:
        with open(dhclient_cfg, "w") as fp:
            fp.write("timeout 10;\n")
    except:
        return (None, None, True)

    # run DHCP client as a child process
    dhclient_pid = run_child("dhclient -d -4 --no-pid -cf \"{}\" " \
        "-lf \"{}\" --no-pid -sf /usr/sbin/dhclient-script -pf /dev/null {}" \
        .format(dhclient_cfg, dhclient_lea, net_iface))

    # check that dhclient doesn't immediately terminate
    try:
        # this raises an OSError if the PID is invalid
        time.sleep(5)
        os.kill(dhclient_pid, 0)
    except:
        return (None, [dhclient_cfg, dhclient_lea], True)

    return (dhclient_pid, [dhclient_cfg, dhclient_lea], False)

def parse_subnet(subnet):
    # split subnet and network prefix
    tmp = subnet.split("/")
    if len(tmp) != 2:
        return None

    prefix = tmp[0].split(".")

    # IP prefix needs to have 4 parts (as we're using IPv4)
    if len(prefix) != 4:
        return None

    # convert to everything to integers
    try:
        prefix = [int(x) for x in prefix]
        mask = int(tmp[1])
    except:
        return None

    # because the ip command doesn't accept netmask directly
    prefix_length = mask

    # convert prefix to 32-bit integer
    prefix = ((prefix[0] & 0xFF) << 24) \
        | ((prefix[1] & 0xFF) << 16) \
        | ((prefix[2] & 0xFF) << 8) \
        | (prefix[3] & 0xFF)

    # generate subnet mask
    tmp = 0
    while mask > 0:
        tmp |= 1 << (32 - mask)
        mask -= 1
    mask = tmp
    
    # make sure the subnet part of prefix is zeroed
    prefix &= mask

    # generate relevant addresses
    first = prefix + 1
    secnd = prefix + 2
    last  = prefix + (0xFFFFFFFF & ~mask) - 1

    return (int_to_addr(first), int_to_addr(secnd), \
        int_to_addr(last), int_to_addr(prefix), \
            int_to_addr(mask), prefix_length)

def dhcp_server_init(net_iface, subnet):
    dhcpd_pid = None
    dhcpd_cfg = "/tmp/dhcpd_mesh.conf"
    dhcpd_lea = "/tmp/dhcpd_mesh.leases"

    # parse subnet into addresses
    tmp = parse_subnet(subnet)
    if tmp == None:
        return (None, None, True)
    router, first, last, prefix, mask, prefix_length = tmp

    # write config (as the full feature set
    # can not be configured via command line)
    try:
        with open(dhcpd_cfg, "w") as fp:
            fp.write("option subnet-mask {};\n".format(mask))
            fp.write("option routers {};\n".format(router))
            fp.write("subnet {} netmask {} {{\n".format(prefix, mask))
            fp.write("\trange {} {};\n".format(first, last))
            fp.write("}\n")

        # lease file needs to be created
        with open(dhcpd_lea, "w") as fp:
            pass
    except:
        return (None, [dhcpd_cfg, dhcpd_lea], True)

    # attempt to configure network interface
    if cmd("ip addr add {}/{} dev {}" \
        .format(router, prefix_length, net_iface)):
        return (None, dhcpd_cfg, True)

    # run DHCP server as a child process
    dhcpd_pid = run_child("dhcpd -f -4 --no-pid -cf \"{}\" " \
        "-lf \"{}\" -pf /dev/null -tf /dev/null {}" \
        .format(dhcpd_cfg, dhcpd_lea, net_iface))

    # check that dhcpd doesn't immediately terminate
    try:
        # this raises an OSError if the PID is invalid
        time.sleep(2)
        os.kill(dhcpd_pid, 0)
    except:
        return (None, [dhcpd_cfg, dhcpd_lea], True)

    return (dhcpd_pid, [dhcpd_cfg, dhcpd_lea], False)

def dhcp_clean(pid, files):
    # terminate program
    if pid != None:
        try:
            print("Terminating {} (mesh)" \
                .format(os.path.basename(files[0]) \
                    .split("_")[0]), file=sys.stderr)
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except:
            pass

    # remove temporary files
    if files:
        for file in files:
            try:
                os.remove(file)
            except:
                pass

# extract and delete a line from bytesarray()
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
            
# test internet connectivity with a HTTP HEAD request
def inet_check(host):
    try:
        # open a HTTP connection
        c = http.client.HTTPConnection(host)
        c.connect()

        # request document root
        c.request("HEAD", "/")

        # discard response
        r = c.getresponse()
        r.read()

        # close connection
        c.close()

    # socket errors (likely) mean we
    # don't have internet connectivity
    except socket.error:
        return True

    return False

# simple UDP broadcast echo server/client (for testing)
def udp_echo(net_iface):
    # UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # enable broadcast and address re-use
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # bind to interface (25 == SO_BINDTODEVICE, this is Linux specific)
    s.setsockopt(socket.SOL_SOCKET, 25, bytes(net_iface, "utf-8") + b'\0')

    # bind to any address (on the bound interface)
    s.bind(("0.0.0.0", 1337))

    # using the poll() syscall allows us to do parallel
    # IO on multiple file descriptors in a single thread
    poll = select.poll()

    # we don't need to poll for POLLOUT on the socket
    # as writing to a UDP socket will never block (under normal circumstances)
    poll.register(sys.stdin.fileno(), select.POLLIN)
    poll.register(s.fileno(), select.POLLIN)

    # buffers
    recv = bytearray()
    send = bytearray()

    print("UDP Echo server/client:", file=sys.stderr)

    # allow the IO loop to be terminated by:
    # 1. CTRL+C (SIGTERM) 
    # 2. CTRL+D (closing stdin)
    try:
        while not sys.stdin.closed:
            for fd, mask in poll.poll():
                # stdin
                if fd == sys.stdin.fileno():
                    # read from stdin
                    send += os.read(fd, 1)

                    tmp = line_read(send)
                    if tmp:
                        #print("LOCAL: '{}'".format(str(tmp, "utf-8")))
                        s.sendto(tmp + b"\n", ("255.255.255.255", 1337))

                # socket
                if fd == s.fileno():
                    # read from socket
                    tmp = s.recvfrom(select.PIPE_BUF)
                    addr = tmp[1][0]
                    recv += tmp[0]

                    # attempt to find a line
                    tmp = line_read(recv)
                    if tmp:
                        print("REMOTE ({}): {}" \
                            .format(addr, str(tmp, "utf-8")))

                # error
                if (mask & (select.POLLERR \
                    | select.POLLNVAL | select.POLLHUP)):
                    break

    except KeyboardInterrupt:
        pass

    # unregister file descriptors
    poll.unregister(sys.stdin.fileno())
    poll.unregister(s.fileno())

    # close socket
    s.close()

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

status = True

def get_status():
    global status
    return b"HIGH" if status else b"LOW"

def set_status():
    global status
    status = not status

    # use the LCD background brigthness as a payload
    try:
        # select backlight backend
        tmp = os.listdir("/sys/class/backlight")
        if "intel_backlight" in tmp:
            backlight = "intel_backlight"
        else:
            backlight = tmp[0]

        # get max brightness
        with open("/sys/class/backlight" \
            "/{}/max_brightness".format(backlight)) as fp:
            max_brightness = int(fp.read())

        # calculate new brightness
        target = max_brightness if status else int(0.1*max_brightness)

        # set brightness
        with open("/sys/class/backlight" \
            "/{}/brightness".format(backlight), "w") as fp:
            fp.write(str(target))

    except Exception as e:
        import traceback
        print(traceback.format_exc())

    return status

def client_main():
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
    s.connect(("server.ovaska.inet", 25565))

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

def main():
    # how long to wait for links
    LINK_WAIT = 10

    # B.A.T.M.A.N. interface
    BAT_IFACE = "bat0"

    # subnet for the mesh
    SUBNET = "172.16.0.0/24"

    # we need to run as root in order to load kernel
    # modules and configure network interfaces, after
    # this we could perhaps drop privileges with a
    # separate user however this is unimplemented
    if (os.getuid() != 0) or (os.getgid() != 0):
        print("This program needs to be run as root.", file=sys.stderr)
        return 1

    print("Initializing B.A.T.M.A.N....", file=sys.stderr)

    # configure B.A.T.M.A.N.
    tmp = bat_init(BAT_IFACE)
    atexit.register(bat_clean, *tmp[:-1])
    if tmp[-1]:
        print("Failed to initialize B.A.T.M.A.N.", file=sys.stderr)
        return 1

    print("Initializing modem...")

    # attempt to initialize a modem
    tmp = modem_init(BAT_IFACE)
    atexit.register(modem_clean, *tmp[:-1])
    if tmp[-1]:
        print("Modem initialization failed, using " \
            "non-link configuration.", file=sys.stderr)
        mode = Mode.NONLINK

    # if we a modem was successfully initialized, use NETLINK mode
    else:
        print("Modem initialized, using net-link " \
            "configuration.", file=sys.stderr)
        mode = Mode.NETLINK

    # wait for links
    print("Waiting {} seconds for B.A.T.M.A.N. links..." \
        .format(LINK_WAIT), file=sys.stderr)
    time.sleep(LINK_WAIT)

    # detect DHCP servers. for some bizarre reason, it takes
    # a long time for the gateway node to respond, so wait at least 10 seconds
    print("Detecting DHCP servers in the mesh...", file=sys.stderr)
    tmp = dhcp_detect(BAT_IFACE, 10)

    if len(tmp) > 0:
        print("Found DHCP servers: {}".format(", ".join(tmp)), file=sys.stderr)
        print("Attempting DHCP autoconfiguration...", file=sys.stderr)

        tmp = dhcp_client_init(BAT_IFACE)
        atexit.register(dhcp_clean, *tmp[:-1])
        if tmp[-1]:
            print("DHCP autoconfiguration failed.", file=sys.stderr)
            return 1

    # No DHCP server
    else:
        # This node can become the gateway if a modem exists
        if mode == Mode.NETLINK:
            print("No DHCP servers, using gateway configuration.", \
                file=sys.stderr)
            print("Starting DHCP server...", file=sys.stderr)

            tmp = dhcp_server_init(BAT_IFACE, SUBNET)
            atexit.register(dhcp_clean, *tmp[:-1])
            if tmp[-1]:
                print("Failed to start DHCP server.", file=sys.stderr)
                return 1

            mode = Mode.GATEWAY

        # We have no connectivity until a gateway node connects
        else:
            print("Waiting for a DHCP server...", file=sys.stderr)
            while 1:
                tmp = dhcp_detect(BAT_IFACE, 5)
                if len(tmp) > 0:
                    break

            print("Found DHCP servers: {}".format(", ".join(tmp)), \
                file=sys.stderr)
            print("Attempting DHCP autoconfiguration...", file=sys.stderr)

            tmp = dhcp_client_init(BAT_IFACE)
            atexit.register(dhcp_clean, *tmp[:-1])
            if tmp[-1]:
                print("DHCP autoconfiguration failed.", file=sys.stderr)
                return 1

    # you may want to change server.ovaska.inet
    # to something that resolves on your machine
    print("Waiting for internet connectivity...", file=sys.stderr)
    while inet_check("server.ovaska.inet"):
        time.sleep(5)

    # simple udp broadcast echo server loop (for testing)
    #udp_echo(BAT_IFACE)

    # restart client on errors
    while 1:
        try:
            client_main()
            break
        except Exception as e:
            print("client_main(): Exception '{}', " \
                "restarting in 5 seconds.".format(e))
            time.sleep(5)

    return 0

if __name__ == "__main__":
    sys.exit(main())
