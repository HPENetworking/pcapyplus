# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
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
)

__author__ = 'Hewlett Packard Enterprise Development LP'
__email__ = 'sdk_tools_frameworks@groups.ext.hpe.com'
__version__ = '0.1.0'


def open_live(device, snaplen, promisc, to_ms):
    """
    Obtain a packet capture descriptor to look at packets on the network.

    open_live is used to obtain a packet capture descriptor to look at packets
    on the network.

    :param str device: the network device to open; on Linux systems with 2.2 or
     later kernels, a device argument of any or NULL can be used to
     capture packets from all interfaces.
    :param int snaplen: the maximum number of bytes to capture.
    :param int promisc: if the interface is to be put into promiscuous mode.
     Note that even if this parameter is false, the interface could well be in
     promiscuous mode for some other reason.
     For now, this doesn't work on the any device; if an argument of any or
     NULL is supplied, the promisc flag is ignored.
    :param int to_ms: the read timeout in milliseconds. The read timeout is
     used to arrange that the read not necessarily return immediately when a
     packet is seen, but that it wait for some amount of time to allow more
     packets to arrive and to read multiple packets from the OS kernel in one
     operation. Not all platforms support a read timeout; on platforms that
     don't, the read timeout is ignored.

    :return: A Reader object.
    :rtype: :py:obj:`Reader`
    """
    return _open_live()


def open_offline():
    """
    FIXME DOC open_offline
    """
    return _open_offline()


def lookupdev():
    """
    Compatibility function, as the original libpcap function was deprecated.

    Notes from libpcap:

        We're deprecating pcap_lookupdev() for various reasons (not
        thread-safe, can behave weirdly with WinPcap).
        Callers should use pcap_findalldevs() and use the first device.
    """
    return _findalldevs()[0]


def findalldevs():
    """
    FIXME DOC findalldevs
    """
    return _findalldevs()


def compile():
    """
    FIXME DOC compile
    """
    return _compile()


def create():
    """
    FIXME DOC create
    """
    return _create()


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
"""

DLT_IEEE802 = _DLT_IEEE802
"""
"""

DLT_ARCNET = _DLT_ARCNET
"""
"""

DLT_SLIP = _DLT_SLIP
"""
"""

DLT_PPP = _DLT_PPP
"""
"""

DLT_FDDI = _DLT_FDDI
"""
"""

DLT_ATM_RFC1483 = _DLT_ATM_RFC1483
"""
"""

DLT_RAW = _DLT_RAW
"""
"""

DLT_PPP_SERIAL = _DLT_PPP_SERIAL
"""
"""

DLT_PPP_ETHER = _DLT_PPP_ETHER
"""
"""

DLT_C_HDLC = _DLT_C_HDLC
"""
"""

DLT_IEEE802_11 = _DLT_IEEE802_11
"""
"""

DLT_LOOP = _DLT_LOOP
"""
"""

DLT_LINUX_SLL = _DLT_LINUX_SLL
"""
"""

DLT_LTALK = _DLT_LTALK
"""
"""

PCAP_D_INOUT = _PCAP_D_INOUT
"""
"""

PCAP_D_IN = _PCAP_D_IN
"""
"""

PCAP_D_OUT = _PCAP_D_OUT
"""
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
]
