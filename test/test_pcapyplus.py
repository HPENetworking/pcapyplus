# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
# Copyright (C) 2014-2021 CORE Security Technologies
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
Tests to check valid package version.
"""

import os
import sys
from pathlib import Path

import pytest
import packaging.version

import pcapyplus


_96PINGS = str(Path(__file__).parent / '96pings.pcap')
IFACE = 'vboxnet0'


def test_version():
    """
    Check that version is PEP 440 compliant.

        https://www.python.org/dev/peps/pep-0440/

    This is basically the basic test to bootstrap a pytest testing suite.
    """
    assert (
        packaging.version.parse(pcapyplus.__version__) >=
        packaging.version.parse('0.1.0')
    )


def test_packet_header_ref_count():
    """
    #1: when next() creates a pkthdr it makes one extra reference
    """

    class _Simple:
        pass

    r = pcapyplus.open_offline(_96PINGS)

    # get one & check its refcount
    assert sys.getrefcount(r.next()[0]) == sys.getrefcount(_Simple())


def test_eof_value():
    """
    #2 empty string is returned as packet body at end of file
    """

    r = pcapyplus.open_offline(_96PINGS)
    # get one & check its refcount

    i = 0
    refnone = sys.getrefcount(None)  # noqa
    hdr, pkt = r.next()
    while hdr is not None:
        hdr, pkt = r.next()
        i += 1
    assert 96 == i
    assert hdr is None
    assert pkt == b''
    del hdr

    # FIXME: This assert fails in upstream.
    # assert refnone == sys.getrefcount(None)


def test_bpf_filter():
    """
    #3 test offline BPFFilter
    """
    r = pcapyplus.open_offline(_96PINGS)
    bpf = pcapyplus.BPFProgram('ip dst host 192.168.1.1')

    hdr, pkt = r.next()
    while hdr is not None:
        f = bpf.filter(pkt)
        assert f != 0
        hdr, pkt = r.next()


@pytest.mark.skip(reason='requires interface info')
def test_live_capture():
    """
    #4 test live capture
    """
    r = pcapyplus.open_live(IFACE, 60000, 1, 1500)
    net = r.getnet()
    assert net == '192.168.56.0'
    hdr, body = r.next()
    assert hdr is not None


@pytest.mark.skip(reason='requires interface info')
def test_send_packet():
    """
    #5 test sendpacket
    """
    r = pcapyplus.open_offline(_96PINGS)
    w = pcapyplus.open_live(IFACE, 60000, 1, 1500)
    # get one & check its refcount

    i = 0
    hdr, pkt = r.next()
    while hdr is not None:
        w.sendpacket(pkt)
        hdr, pkt = r.next()
        i += 1


def test_packet_dumper():
    """
    #6 test that the dumper writes correct payload
    """
    try:
        r = pcapyplus.open_offline(_96PINGS)
        dumper = r.dump_open('tmp.pcap')

        hdr, body = r.next()
        i = 0
        while hdr is not None:
            dumper.dump(hdr, body)
            i += 1
            hdr, body = r.next()

        # make sure file closes
        del dumper

        # check that the dumper wrote a legal pcap
        # file with same packer data
        r = pcapyplus.open_offline(_96PINGS)
        r2 = pcapyplus.open_offline('tmp.pcap')

        h1, b1 = r.next()
        h2, b2 = r2.next()
        while h1 is not None and h2 is not None:
            assert b1 == b2
            h1, b1 = r.next()
            h2, b2 = r2.next()

        assert h1 is None
        assert h2 is None
        del r2
    finally:
        os.unlink('tmp.pcap')


def test_close():
    """
    #7 Test the close method
    """
    r = pcapyplus.open_offline(_96PINGS)
    hdr, body = r.next()
    assert hdr is not None
    r.close()

    with pytest.raises(ValueError):
        r.next()


def test_context_manager():
    """
    #8 Test the context manager support
    """
    with pcapyplus.open_offline(_96PINGS) as r:
        hdr, body = r.next()
        assert hdr is not None

    with pytest.raises(ValueError):
        r.next()


def test_get_bpf():
    bpf = pcapyplus.compile(pcapyplus.DLT_EN10MB, 2**16, 'icmp', 1, 1)
    code = bpf.get_bpf()

    # result of `tcpdump "icmp" -ddd -s 65536` on EN10MB interface
    expected = """6
40 0 0 12
21 0 3 2048
48 0 0 23
21 0 1 1
6 0 0 65536
6 0 0 0"""

    result = str(len(code)) + '\n'
    result += '\n'.join(
        ' '.join(map(str, inst)) for inst in code
    )

    assert expected == result
