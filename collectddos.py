import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from datetime import datetime


class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.logger.debug("register datapath: %016x", dp.id)
                self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.debug("unregister datapath: %016x", dp.id)
                del self.datapaths[dp.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(2)     # shorter interval to catch brief DDoS flows

    def request_stats(self, dp):
        self.logger.debug("send stats request: %016x", dp.id)
        parser = dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Collect flow stats safely: handles flows that may lack eth_type/ipv4_src/etc.
        """
        ts = datetime.now().timestamp()

        with open("FlowStatsfile.csv", "a+") as f:
            for stat in ev.msg.body:
                m = stat.match  # shorthand

                # Extract match fields with safe defaults
                eth_type = m.get("eth_type", 0)
                ip_src   = m.get("ipv4_src", "0.0.0.0")
                ip_dst   = m.get("ipv4_dst", "0.0.0.0")
                ip_proto = m.get("ip_proto", 0)

                icmp_code = m.get("icmpv4_code", -1)
                icmp_type = m.get("icmpv4_type", -1)
                tp_src = m.get("tcp_src", m.get("udp_src", 0))
                tp_dst = m.get("tcp_dst", m.get("udp_dst", 0))

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                # Rates with safe division
                try:
                    pkt_per_s = stat.packet_count / max(stat.duration_sec, 1)
                except ZeroDivisionError:
                    pkt_per_s = 0
                try:
                    pkt_per_ns = stat.packet_count / max(stat.duration_nsec, 1)
                except ZeroDivisionError:
                    pkt_per_ns = 0
                try:
                    byte_per_s = stat.byte_count / max(stat.duration_sec, 1)
                except ZeroDivisionError:
                    byte_per_s = 0
                try:
                    byte_per_ns = stat.byte_count / max(stat.duration_nsec, 1)
                except ZeroDivisionError:
                    byte_per_ns = 0

                # Write CSV row: label=1 for DDoS traffic
                f.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                        .format(ts, ev.msg.datapath.id, flow_id,
                                ip_src, tp_src, ip_dst, tp_dst,
                                ip_proto, icmp_code, icmp_type,
                                stat.duration_sec, stat.duration_nsec,
                                stat.idle_timeout, stat.hard_timeout,
                                stat.flags, stat.packet_count, stat.byte_count,
                                pkt_per_s, pkt_per_ns,
                                byte_per_s, byte_per_ns,
                                1))

