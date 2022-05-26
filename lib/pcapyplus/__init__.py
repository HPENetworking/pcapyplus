# -*- coding: utf-8 -*-
#
# Copyright (C) 2021-2022 Hewlett Packard Enterprise Development LP.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.


"""
pcapyplus module entry point.
"""

from ._pcapyplus import (
    # Functions
    open_live as _open_live,
    open_offline as _open_offline,
    findalldevs as _findalldevs,
    compile as _compile,
    create as _create,

    # Constants
    DLT_NULL as _DLT_NULL,
    DLT_EN10MB as _DLT_EN10MB,
    DLT_IEEE802 as _DLT_IEEE802,
    DLT_ARCNET as _DLT_ARCNET,
    DLT_SLIP as _DLT_SLIP,
    DLT_PPP as _DLT_PPP,
    DLT_FDDI as _DLT_FDDI,
    DLT_ATM_RFC1483 as _DLT_ATM_RFC1483,
    DLT_RAW as _DLT_RAW,
    DLT_PPP_SERIAL as _DLT_PPP_SERIAL,
    DLT_PPP_ETHER as _DLT_PPP_ETHER,
    DLT_C_HDLC as _DLT_C_HDLC,
    DLT_IEEE802_11 as _DLT_IEEE802_11,
    DLT_LOOP as _DLT_LOOP,
    DLT_LINUX_SLL as _DLT_LINUX_SLL,
    DLT_LTALK as _DLT_LTALK,
    PCAP_D_INOUT as _PCAP_D_INOUT,
    PCAP_D_IN as _PCAP_D_IN,
    PCAP_D_OUT as _PCAP_D_OUT,

    # Classes
    Reader,
    BPFProgram,
    Dumper,
    Pkthdr,
)

__author__ = 'Hewlett Packard Enterprise Development LP'
__email__ = 'sdk_tools_frameworks@groups.ext.hpe.com'
__version__ = '1.0.1'


def open_live(device, snaplen, promisc, to_ms):
    """
    Obtain a packet capture descriptor to look at packets on the network.

    :param str device: Network device to open; on Linux systems with 2.2 or
     later kernels, a device argument of any or NULL can be used to
     capture packets from all interfaces.
    :param int snaplen: Maximum number of bytes to capture.
    :param int promisc: Wheter the interface is to be put in promiscuous mode.
     Note that even if this parameter is false, the interface could well be in
     promiscuous mode for some other reason.
     For now, this doesn't work on the any device; if an argument of any or
     NULL is supplied, the promisc flag is ignored.
    :param int to_ms: Read timeout in milliseconds. The read timeout is
     used to arrange that the read not necessarily return immediately when a
     packet is seen, but that it wait for some amount of time to allow more
     packets to arrive and to read multiple packets from the OS kernel in one
     operation. Not all platforms support a read timeout; on platforms that
     don't, the read timeout is ignored.

    :return: A Reader object.
    :rtype: :py:obj:`Reader`
    """
    return _open_live(device, snaplen, promisc, to_ms)


def open_offline(filename):
    """
    Obtain a packet capture descriptor to look at packets on a savefile.

    open_offline is called to open a savefile for reading.

    :param str filename: Name of the file to open. The file has the same format
     as those used by tcpdump(8) and tcpslice(8). The name - is a synonym
     for stdin.

    :return: A Reader object.
    :rtype: :py:obj:`Reader`
    """
    return _open_offline(filename)


def lookupdev():
    """
    Compatibility function, as the original libpcap function was deprecated.

    Return a network device suitable for use with open_live.

    Notes from libpcap:

        We're deprecating pcap_lookupdev() for various reasons (not
        thread-safe, can behave weirdly with WinPcap).
        Callers should use pcap_findalldevs() and use the first device.
    """
    return _findalldevs()[0]


def findalldevs():
    """
    Obtain the list of available network devices.

    findalldevs constructs a list of network devices that can be opened with
    :py:func:`open_live`.

    .. note::

       There may be network devices that cannot be opened with
       :py:func:`open_live`, because, for example, that process might not have
       sufficient privileges to open them for capturing; if so, those devices
       will not appear on the list.

    :return: A list of strings with the network device names.
    :rtype: list
    """
    return _findalldevs()


def compile(linktype, snaplen, filter, optimize, netmask):
    """
    Compile a BPF filter into a filter program.

    :param int linktype: Type of the link to be used by the filter.
    :param int snaplen: Maximum number of bytes to capture.
    :param str filter: BPF filter to be compiled.
    :param int optimize: Controls whether optimization on the resulting code
     is performed
    :param int netmask: Netmask of the local network.

    :return: A BPFProgram object.
    :rtype: :py:obj:`BPFProgram`
    """
    return _compile(linktype, snaplen, filter, optimize, netmask)


def create(filter):
    """
    Creates a non-activated packet capture handle to look at packets on the
    network.

    create is used to create a packet capture handle to look at packets on the
    network. The returned handle must be activated with activate() before
    packets can be captured with it; options for the capture, such as
    promiscuous mode, can be set on the handle before activating it.

    :param str filter: Device name to be created.

    :return: A Reader object.
    :rtype: :py:obj:`Reader`
    """
    return _create(filter)


DLT_NULL = _DLT_NULL
"""
BSD loopback encapsulation; the link layer header is a 4-byte field, in host
byte order, containing a ``PF_`` value from socket.h for the network-layer
protocol of the packet.

.. note::

   "host byte order" is the byte order of the machine on which the packets are
   captured, and the ``PF_`` values are for the OS of the machine on which the
   packets are captured; if a live capture is being done, "host byte order" is
   the byte order of the machine capturing the packets, and the ``PF_`` values
   are those of the OS of the machine capturing the packets, but if a savefile
   is being read, the byte order and ``PF_`` values are not necessarily those
   of the machine reading the capture file.
"""

DLT_EN10MB = _DLT_EN10MB
"""
Ethernet (10Mb, 100Mb, 1000Mb, and up)
"""

DLT_IEEE802 = _DLT_IEEE802
"""
IEEE 802.5 Token Ring
"""

DLT_ARCNET = _DLT_ARCNET
"""
ARCNET
"""

DLT_SLIP = _DLT_SLIP
"""
SLIP; the link layer header contains, in order:

* a 1-byte flag, which is 0 for packets received by the machine and 1 for
  packets sent by the machine.
* a 1-byte field, the upper 4 bits of which indicate the type of packet, as
  per RFC 1144:

  * 0x40; an unmodified IP datagram (TYPE_IP).
  * 0x70; an uncompressed-TCP/IP datagram (UNCOMPRESSED_TCP), with that byte
    being the first byte of the raw IP header on the wire, containing the
    connection number in the protocol field.
  * 0x80; a compressed-TCP/IP datagram (COMPRESSED_TCP), with that byte being
    the first byte of the compressed TCP/IP datagram header.
* for UNCOMPRESSED_TCP, the rest of the modified IP header, and for
  COMPRESSED_TCP, the compressed TCP/IP datagram header.
"""

DLT_PPP = _DLT_PPP
"""
PPP; if the first 2 bytes are 0xff and 0x03, it's PPP in HDLC-like framing,
with the PPP header following those two bytes, otherwise it's PPP without
framing, and the packet begins with the PPP header.
"""

DLT_FDDI = _DLT_FDDI
"""
FDDI
"""

DLT_ATM_RFC1483 = _DLT_ATM_RFC1483
"""
RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an IEEE 802.2 LLC
header.
"""

DLT_RAW = _DLT_RAW
"""
Raw IP; the packet begins with an IP header.
"""

DLT_PPP_SERIAL = _DLT_PPP_SERIAL
"""
PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing,
as per section 4.3.1 of RFC 1547; the first byte will be 0xFF for PPP in
HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing.
"""

DLT_PPP_ETHER = _DLT_PPP_ETHER
"""
PPPoE; the packet begins with a PPPoE header, as per RFC 2516.
"""

DLT_C_HDLC = _DLT_C_HDLC
"""
Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547.
"""

DLT_IEEE802_11 = _DLT_IEEE802_11
"""
IEEE 802.11 wireless LAN.
"""

DLT_LOOP = _DLT_LOOP
"""
OpenBSD loopback encapsulation; the link layer header is a 4-byte field,
in network byte order, containing a ``PF_`` value from OpenBSD's socket.h for
the network-layer protocol of the packet.

.. note::

   Note that, if a savefile is being read, those ``PF_`` values are not
   necessarily those of the machine reading the capture file.
"""

DLT_LINUX_SLL = _DLT_LINUX_SLL
"""
Linux cooked capture encapsulation; the link layer header contains, in order:

* a 2-byte "packet type", in network byte order, which is one of:

  * 0; packet was sent to us by somebody else.
  * 1; packet was broadcast by somebody else.
  * 2; packet was multicast, but not broadcast, by somebody else.
  * 3; packet was sent by somebody else to somebody else.
  * 4; packet was sent by us.
* a 2-byte field, in network byte order, containing a Linux ``ARPHRD_`` value
  for the link layer device type.
* a 2-byte field, in network byte order, containing the length of the link
  layer address of the sender of the packet (which could be 0).
* an 8-byte field containing that number of bytes of the link layer header
  (if there are more than 8 bytes, only the first 8 are present).
* a 2-byte field containing an Ethernet protocol type, in network byte order,
  or containing 1 for Novell 802.3 frames without an 802.2 LLC header or 4 for
  frames beginning with an 802.2 LLC header.
"""

DLT_LTALK = _DLT_LTALK
"""
Apple LocalTalk; the packet begins with an AppleTalk LLAP header.
"""

PCAP_D_INOUT = _PCAP_D_INOUT
"""
will capture packets received by or sent by the device.
"""

PCAP_D_IN = _PCAP_D_IN
"""
Will only capture packets received by the device.
"""

PCAP_D_OUT = _PCAP_D_OUT
"""
Will only capture packets sent by the device.
"""


__all__ = [
    # Functions
    'open_live',
    'open_offline',
    'lookupdev',
    'findalldevs',
    'compile',
    'create',

    # Constants
    "DLT_NULL",
    "DLT_EN10MB",
    "DLT_IEEE802",
    "DLT_ARCNET",
    "DLT_SLIP",
    "DLT_PPP",
    "DLT_FDDI",
    "DLT_ATM_RFC1483",
    "DLT_RAW",
    "DLT_PPP_SERIAL",
    "DLT_PPP_ETHER",
    "DLT_C_HDLC",
    "DLT_IEEE802_11",
    "DLT_LOOP",
    "DLT_LINUX_SLL",
    "DLT_LTALK",
    "PCAP_D_INOUT",
    "PCAP_D_IN",
    "PCAP_D_OUT",

    # Classes
    'Reader',
    'BPFProgram',
    'Dumper',
    'Pkthdr',
]
