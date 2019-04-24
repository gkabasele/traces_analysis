#!/bin/env python3
# vim: ts=4 sts=4 sw=4 ft=python expandtab :

import ctypes
import socket


class TcpInfo(ctypes.Structure):
    """TCP_INFO struct in linux 4.2
    see /usr/include/linux/tcp.h for details"""

    __u8 = ctypes.c_uint8
    __u32 = ctypes.c_uint32
    __u64 = ctypes.c_uint64

    _fields_ = [
        ("tcpi_state", __u8),
        ("tcpi_ca_state", __u8),
        ("tcpi_retransmits", __u8),
        ("tcpi_probes", __u8),
        ("tcpi_backoff", __u8),
        ("tcpi_options", __u8),
        ("tcpi_snd_wscale", __u8, 4), ("tcpi_rcv_wscale", __u8, 4),

        ("tcpi_rto", __u32),
        ("tcpi_ato", __u32),
        ("tcpi_snd_mss", __u32),
        ("tcpi_rcv_mss", __u32),

        ("tcpi_unacked", __u32),
        ("tcpi_sacked", __u32),
        ("tcpi_lost", __u32),
        ("tcpi_retrans", __u32),
        ("tcpi_fackets", __u32),

        # Times
        ("tcpi_last_data_sent", __u32),
        ("tcpi_last_ack_sent", __u32),
        ("tcpi_last_data_recv", __u32),
        ("tcpi_last_ack_recv", __u32),
        # Metrics
        ("tcpi_pmtu", __u32),
        ("tcpi_rcv_ssthresh", __u32),
        ("tcpi_rtt", __u32),
        ("tcpi_rttvar", __u32),
        ("tcpi_snd_ssthresh", __u32),
        ("tcpi_snd_cwnd", __u32),
        ("tcpi_advmss", __u32),
        ("tcpi_reordering", __u32),

        ("tcpi_rcv_rtt", __u32),
        ("tcpi_rcv_space", __u32),

        ("tcpi_total_retrans", __u32),

        ("tcpi_pacing_rate", __u64),
        ("tcpi_max_pacing_rate", __u64),

        # RFC4898 tcpEStatsAppHCThruOctetsAcked
        ("tcpi_bytes_acked", __u64),
        # RFC4898 tcpEStatsAppHCThruOctetsReceived
        ("tcpi_bytes_received", __u64),
        # RFC4898 tcpEStatsPerfSegsOut
        ("tcpi_segs_out", __u32),
        # RFC4898 tcpEStatsPerfSegsIn
        ("tcpi_segs_in", __u32),
    ]
    del __u8, __u32, __u64

    def __repr__(self):
        keyval = ["{}={!r}".format(x[0], getattr(self, x[0]))
                  for x in self._fields_]
        fields = ", ".join(keyval)
        return "{}({})".format(self.__class__.__name__, fields)

    @classmethod
    def from_socket(cls, sock):
        """Takes a socket, and attempts to get TCP_INFO stats on it. Returns a
        TcpInfo struct"""
        # http://linuxgazette.net/136/pfeiffer.html
        padsize = ctypes.sizeof(TcpInfo)
        data = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, padsize)
        # On older kernels, we get fewer bytes, pad with null to fit
        padded = data.ljust(padsize, b'\0')
        return cls.from_buffer_copy(padded)


def get_info_from_curl(curl):
    """ curl is supposed to be a pycurl.Curl() object"""
    sockfd = curl.getinfo(curl.LASTSOCKET)
    try:
        sock = socket.fromfd(sockfd, socket.AF_INET, socket.SOCK_STREAM)
        return TcpInfo.from_socket(sock)
    except Exception:
        return None

if __name__ == "__main__":
    print("This spot intentionally left empty")
