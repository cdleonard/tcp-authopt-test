import ctypes
import socket
from ctypes import c_uint8, c_uint32, c_uint64


class tcp_info(ctypes.Structure):
    """Wrapper for result of linux TCP_INFO sockopt"""

    _fields_ = [
        ("tcpi_state", c_uint8),
        ("tcpi_ca_state", c_uint8),
        ("tcpi_retransmits", c_uint8),
        ("tcpi_probes", c_uint8),
        ("tcpi_backoff", c_uint8),
        ("tcpi_options", c_uint8),
        ("tcpi_snd_wscale", c_uint8, 4),
        ("tcpi_rcv_wscale", c_uint8, 4),
        ("tcpi_delivery_rate_app_limited", c_uint8, 1),
        ("tcpi_rto", c_uint32),
        ("tcpi_ato", c_uint32),
        ("tcpi_snd_mss", c_uint32),
        ("tcpi_rcv_mss", c_uint32),
        ("tcpi_unacked", c_uint32),
        ("tcpi_sacked", c_uint32),
        ("tcpi_lost", c_uint32),
        ("tcpi_retrans", c_uint32),
        ("tcpi_fackets", c_uint32),
        ("tcpi_last_data_sent", c_uint32),
        ("tcpi_last_ack_sent", c_uint32),
        ("tcpi_last_data_recv", c_uint32),
        ("tcpi_last_ack_recv", c_uint32),
        ("tcpi_pmtu", c_uint32),
        ("tcpi_rcv_ssthresh", c_uint32),
        ("tcpi_rtt", c_uint32),
        ("tcpi_rttvar", c_uint32),
        ("tcpi_snd_ssthresh", c_uint32),
        ("tcpi_snd_cwnd", c_uint32),
        ("tcpi_advmss", c_uint32),
        ("tcpi_reordering", c_uint32),
        ("tcpi_rcv_rtt", c_uint32),
        ("tcpi_rcv_space", c_uint32),
        ("tcpi_total_retrans", c_uint32),
        ("tcpi_pacing_rate", c_uint64),
        ("tcpi_max_pacing_rate", c_uint64),
        ("tcpi_bytes_acked", c_uint64),
        ("tcpi_bytes_received", c_uint64),
        ("tcpi_segs_out", c_uint32),
        ("tcpi_segs_in", c_uint32),
        ("tcpi_notsent_bytes", c_uint32),
        ("tcpi_min_rtt", c_uint32),
        ("tcpi_data_segs_in", c_uint32),
        ("tcpi_data_segs_out", c_uint32),
        ("tcpi_delivery_rate", c_uint64),
        ("tcpi_busy_time", c_uint64),
        ("tcpi_rwnd_limited", c_uint64),
        ("tcpi_sndbuf_limited", c_uint64),
        ("tcpi_delivered", c_uint32),
        ("tcpi_delivered_ce", c_uint32),
        ("tcpi_bytes_sent", c_uint64),
        ("tcpi_bytes_retrans", c_uint64),
        ("tcpi_dsack_dups", c_uint32),
        ("tcpi_reord_seen", c_uint32),
    ]


def get_tcp_info(sock: socket.socket) -> tcp_info:
    optlen = ctypes.sizeof(tcp_info)
    optval = sock.getsockopt(socket.SOL_TCP, socket.TCP_INFO, optlen)
    return tcp_info.from_buffer_copy(optval.ljust(optlen, b"\0"))
