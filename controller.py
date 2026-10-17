from __future__ import annotations

import json
import mimetypes
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from collections import defaultdict  # noqa: F401

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,  # required
    set_ev_cls,
)
from ryu.lib import hub  # required
from ryu.lib.packet import ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response

from firewall import FirewallEngine
from ddos import DDoSEngine


API_NAME = "sdnsec_api"


def _json_response(payload: Any, status: int = 200) -> Response:
    body = json.dumps(payload, indent=2).encode("utf-8")
    return Response(content_type="application/json", body=body, status=status)


class SDNSecurityRestController(ControllerBase):
    """
    Embedded web controller:
      - Serves static frontend files from ./frontend
      - Exposes REST API endpoints under /api/*
    """

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.sdnapp: "SDNSecurityController" = data["sdnapp"]
        self.frontend_dir: Path = data["frontend_dir"]
        self.policies_dir: Path = data["policies_dir"]

    # -------------------------
    # Static frontend
    # -------------------------
    @route(API_NAME, "/", methods=["GET"])
    def index(self, req, **kwargs):
        return self._serve_file("overview.html")

    @route(API_NAME, "/{filename:.*}", methods=["GET"])
    def serve_static(self, req, filename: str, **kwargs):
        if not filename or filename.endswith("/"):
            filename = "overview.html"
        return self._serve_file(filename)

    def _serve_file(self, filename: str) -> Response:
        base = self.frontend_dir.resolve()
        target = (self.frontend_dir / filename).resolve()

        # prevent path traversal
        if not str(target).startswith(str(base)):
            return Response(status=403, body=b"Forbidden")

        if not target.exists() or not target.is_file():
            return Response(status=404, body=b"Not Found")

        ctype, _ = mimetypes.guess_type(str(target))
        if not ctype:
            ctype = "text/plain"

        return Response(content_type=ctype, body=target.read_bytes(), status=200)

    # -------------------------
    # REST API
    # -------------------------
    @route(API_NAME, "/api/health", methods=["GET"])
    def api_health(self, req, **kwargs):
        return _json_response({"status": "ok"})

    @route(API_NAME, "/api/overview", methods=["GET"])
    def api_overview(self, req, **kwargs):
        fw = self.sdnapp._read_policy_json(self.sdnapp.firewall_policy_path)
        dd = self.sdnapp._read_policy_json(self.sdnapp.ddos_policy_path)

        rules = fw.get("rules", []) or []
        deny_rules = [r for r in rules if isinstance(r, dict) and str(r.get("action", "")).upper() == "DENY"]

        return _json_response({
            "defaultPolicy": str(fw.get("default_policy", "ALLOW")).upper(),
            "blockedIps": fw.get("blocked_ips", []) or [],
            "blockedIpsCount": len(fw.get("blocked_ips", []) or []),
            "denyRulesCount": len(deny_rules),
            "ddosPolicy": {
                "window_seconds": int(dd.get("window_seconds", 10)),
                "threshold_packets": int(dd.get("threshold_packets", 60)),
                "block_seconds": int(dd.get("block_seconds", 30)),
                "priority": int(dd.get("priority", 260)),
            },
        })

    @route(API_NAME, "/api/firewall/deny-rules", methods=["GET"])
    def api_firewall_deny_rules(self, req, **kwargs):
        fw = self.sdnapp._read_policy_json(self.sdnapp.firewall_policy_path)
        rules = fw.get("rules", []) or []
        deny_rules = [r for r in rules if isinstance(r, dict) and str(r.get("action", "")).upper() == "DENY"]
        return _json_response({"deny_rules": deny_rules})

    @route(API_NAME, "/api/live/traffic", methods=["GET"])
    def api_live_traffic(self, req, **kwargs):
        return _json_response({"interval": self.sdnapp.poll_interval, "points": self.sdnapp.live_points})

    @route(API_NAME, "/api/firewall/blocked-ips", methods=["GET"])
    def api_get_blocked_ips(self, req, **kwargs):
        ips = sorted(map(str, self.sdnapp.firewall.blocked_ips))
        return _json_response({"blocked_ips": ips})

    @route(API_NAME, "/api/firewall/blocked-ips/add", methods=["POST"])
    def api_add_blocked_ip(self, req, **kwargs):
        body = self._parse_json(req)
        ip = str(body.get("ip", "")).strip()
        if not ip:
            return _json_response({"error": "ip is required"}, status=400)

        # update memory
        self.sdnapp.firewall.blocked_ips.add(ip)

        # persist to JSON
        fw = self.sdnapp._read_policy_json(self.sdnapp.firewall_policy_path)
        blocked = set(map(str, fw.get("blocked_ips", []) or []))
        blocked.add(ip)
        fw["blocked_ips"] = sorted(blocked)
        self.sdnapp._write_policy_json(self.sdnapp.firewall_policy_path, fw)

        return _json_response({"added": True, "blocked_ips": fw["blocked_ips"]})

    @route(API_NAME, "/api/firewall/blocked-ips/remove", methods=["POST"])
    def api_remove_blocked_ip(self, req, **kwargs):
        body = self._parse_json(req)
        ip = str(body.get("ip", "")).strip()
        if not ip:
            return _json_response({"error": "ip is required"}, status=400)

        # update memory
        self.sdnapp.firewall.blocked_ips.discard(ip)

        # persist to JSON
        fw = self.sdnapp._read_policy_json(self.sdnapp.firewall_policy_path)
        blocked = set(map(str, fw.get("blocked_ips", []) or []))
        blocked.discard(ip)
        fw["blocked_ips"] = sorted(blocked)
        self.sdnapp._write_policy_json(self.sdnapp.firewall_policy_path, fw)

        return _json_response({"removed": True, "blocked_ips": fw["blocked_ips"]})

    @route(API_NAME, "/api/reload", methods=["POST"])
    def api_reload(self, req, **kwargs):
        try:
            self.sdnapp.reload_policies()
            return _json_response({"reloaded": True})
        except Exception as e:
            return _json_response({"reloaded": False, "error": str(e)}, status=500)

    def _parse_json(self, req) -> Dict[str, Any]:
        try:
            raw = req.body
            if raw is None:
                return {}
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="ignore")
            return json.loads(raw) if raw else {}
        except Exception:
            return {}


class SDNSecurityController(app_manager.RyuApp):
    """
    SDN Security Controller:
      - L2 learning switch forwarding
      - Firewall policy enforcement (JSON)
      - DDoS detection (per-src threshold) with temporary block flow
      - Embedded Web UI + REST API
      - Live Traffic from OpenFlow PortStats
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # (2) Live traffic vars (as required)
        self.datapaths = {}      # dpid -> datapath
        self._port_prev = {}     # (dpid, port_no) -> (rx_bytes, tx_bytes, t)
        self.live_points = []    # rolling points [{t, rx_bps, tx_bps}, ...]
        self.live_window = 60
        self.poll_interval = 2
        self.monitor_thread = hub.spawn(self._monitor_stats)

        # Project structure
        self.base_dir = Path.cwd()
        self.policies_dir = self.base_dir / "policies"
        self.frontend_dir = self.base_dir / "frontend"

        self.firewall_policy_path = str(self.policies_dir / "firewall_policy.json")
        self.ddos_policy_path = str(self.policies_dir / "ddos_policy.json")

        # L2 learning switch table
        self.mac_to_port: Dict[int, Dict[str, int]] = {}

        # Load engines
        self.firewall = FirewallEngine(self.firewall_policy_path)
        self.ddos = DDoSEngine(self.ddos_policy_path)

        # Register WSGI controller
        wsgi: WSGIApplication = kwargs["wsgi"]
        wsgi.register(
            SDNSecurityRestController,
            {
                "sdnapp": self,
                "policies_dir": self.policies_dir,
                "frontend_dir": self.frontend_dir,
            },
        )

        self.logger.info("SDN Security Controller started")
        self.logger.info("Initial blocked IPs: %s", list(self.firewall.blocked_ips))
        self.logger.info("Open dashboard: http://127.0.0.1:8080/overview.html")

    # -------------------------
    # Policy IO
    # -------------------------
    def _read_policy_json(self, path: str) -> Dict[str, Any]:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def _write_policy_json(self, path: str, data: Dict[str, Any]) -> None:
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def reload_policies(self) -> None:
        self.firewall = FirewallEngine(self.firewall_policy_path)
        self.ddos = DDoSEngine(self.ddos_policy_path)
        self.logger.info("Policies reloaded. Blocked IPs now: %s", list(self.firewall.blocked_ips))

    # -------------------------
    # (3) State Change Handler (required)
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Datapath registered: %s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self.logger.info("Datapath unregistered: %s", dp.id)

    # -------------------------
    # (4) Polling: PortStatsRequest (required)
    # -------------------------
    def _monitor_stats(self):
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    self._request_port_stats(dp)
            except Exception as e:
                self.logger.exception("Stats monitor error: %s", e)
            hub.sleep(self.poll_interval)

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # -------------------------
    # (5) PortStatsReply handler (required)
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        body = ev.msg.body
        now = time.time()

        total_rx_bps = 0.0
        total_tx_bps = 0.0

        for stat in body:
            port_no = stat.port_no

            # ignore Local port only
            if port_no == dp.ofproto.OFPP_LOCAL:
                continue

            rx_bytes = float(getattr(stat, "rx_bytes", 0.0) or 0.0)
            tx_bytes = float(getattr(stat, "tx_bytes", 0.0) or 0.0)

            key = (dp.id, port_no)
            prev = self._port_prev.get(key)

            # first time: store only
            if not prev:
                self._port_prev[key] = (rx_bytes, tx_bytes, now)
                continue

            prev_rx, prev_tx, prev_t = prev
            dt = now - prev_t
            if dt <= 0:
                self._port_prev[key] = (rx_bytes, tx_bytes, now)
                continue

            drx = max(0.0, rx_bytes - prev_rx)
            dtx = max(0.0, tx_bytes - prev_tx)

            total_rx_bps += (drx * 8.0) / dt
            total_tx_bps += (dtx * 8.0) / dt

            # update prev
            self._port_prev[key] = (rx_bytes, tx_bytes, now)

        # one aggregated point per reply
        self.live_points.append({
            "t": now,
            "rx_bps": total_rx_bps,
            "tx_bps": total_tx_bps,
        })

        if len(self.live_points) > self.live_window:
            self.live_points = self.live_points[-self.live_window:]

    # -------------------------
    # OpenFlow: Switch features
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Table-miss flow installed on switch %s", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=int(priority),
            match=match,
            instructions=inst,
            idle_timeout=int(idle_timeout),
            hard_timeout=0,
        )
        datapath.send_msg(mod)

    # -------------------------
    # OpenFlow: PacketIn
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dpid = datapath.id
        in_port = msg.match["in_port"]
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == 0x88cc:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port[dpid][src_mac] = in_port

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4:
            src_ip = ip4.src
            dst_ip = ip4.dst
            ip_proto = ip4.proto

            tcp_seg = pkt.get_protocol(tcp.tcp)
            udp_seg = pkt.get_protocol(udp.udp)
            tcp_dst = tcp_seg.dst_port if tcp_seg else None
            udp_dst = udp_seg.dst_port if udp_seg else None

            # DDoS detection
            ddos_block, ddos_prio, block_secs = self.ddos.observe_and_decide(src_ip)
            if ddos_block and ddos_prio:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                FirewallEngine.install_drop_flow(
                    datapath,
                    parser,
                    match,
                    priority=int(ddos_prio),
                    idle_timeout=int(block_secs or 30),
                )
                self.logger.warning("DDoS detected: src_ip=%s blocked for %ss", src_ip, int(block_secs or 30))
                return

            # Firewall rules evaluation
            allowed, match_hint, prio = self.firewall.evaluate_ipv4(src_ip, dst_ip, ip_proto, tcp_dst, udp_dst)
            if not allowed:
                fields = {"eth_type": 0x0800}
                if match_hint:
                    fields.update(match_hint)

                match = parser.OFPMatch(**fields)
                FirewallEngine.install_drop_flow(
                    datapath,
                    parser,
                    match,
                    priority=int(prio or 300),
                    idle_timeout=60,
                )
                self.logger.info("Firewall DROP src=%s dst=%s proto=%s", src_ip, dst_ip, ip_proto)
                return

        # L2 forwarding
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install learned flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            self._add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=120)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)
