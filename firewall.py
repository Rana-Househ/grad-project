import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class FirewallEngine:
    def __init__(self, policy_path: str):
        self.policy_path = str(policy_path)
        self.default_policy: str = "ALLOW"
        self.blocked_ips = set()
        self.rules = []
        self._load_policy()

    def _load_policy(self) -> None:
        policy_file = Path(self.policy_path)
        if not policy_file.exists():
            raise FileNotFoundError(f"Firewall policy not found: {policy_file}")

        data = json.loads(policy_file.read_text(encoding="utf-8"))

        self.default_policy = str(data.get("default_policy", "ALLOW")).upper()
        if self.default_policy not in ("ALLOW", "DENY"):
            self.default_policy = "ALLOW"

        self.blocked_ips = set(map(str, data.get("blocked_ips", [])))
        self.rules = list(data.get("rules", []))

    @staticmethod
    def _proto_to_num(proto: str) -> Optional[int]:
        p = str(proto).upper()
        if p == "TCP":
            return 6
        if p == "UDP":
            return 17
        if p == "ICMP":
            return 1
        return None

    def evaluate_ipv4(
        self,
        src_ip: str,
        dst_ip: str,
        ip_proto: int,
        tcp_dst: Optional[int],
        udp_dst: Optional[int],
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[int]]:
        src_ip = str(src_ip)
        dst_ip = str(dst_ip)

        if src_ip in self.blocked_ips:
            return False, {"ipv4_src": src_ip}, 300
        if dst_ip in self.blocked_ips:
            return False, {"ipv4_dst": dst_ip}, 300

        best_rule: Optional[Dict[str, Any]] = None
        best_prio = -1

        for r in self.rules:
            if not isinstance(r, dict):
                continue

            action = str(r.get("action", "")).upper()
            if action not in ("ALLOW", "DENY"):
                continue

            rule_proto = r.get("proto")
            if rule_proto:
                rule_proto_num = self._proto_to_num(rule_proto)
                if rule_proto_num is None or rule_proto_num != int(ip_proto):
                    continue

            ip_src = r.get("ip_src")
            if ip_src and str(ip_src) != src_ip:
                continue

            ip_dst = r.get("ip_dst")
            if ip_dst and str(ip_dst) != dst_ip:
                continue

            dst_port = r.get("dst_port")
            if dst_port is not None:
                try:
                    dst_port = int(dst_port)
                except (TypeError, ValueError):
                    continue

                if int(ip_proto) == 6:
                    if tcp_dst is None or int(tcp_dst) != dst_port:
                        continue
                elif int(ip_proto) == 17:
                    if udp_dst is None or int(udp_dst) != dst_port:
                        continue
                else:
                    continue

            try:
                pr = int(r.get("priority", 200))
            except (TypeError, ValueError):
                pr = 200

            if pr > best_prio:
                best_prio = pr
                best_rule = r

        if best_rule is None:
            return (self.default_policy == "ALLOW"), None, None

        if str(best_rule.get("action")).upper() == "DENY":
            match_hint: Dict[str, Any] = {
                "ipv4_src": src_ip,
                "ipv4_dst": dst_ip,
                "ip_proto": int(ip_proto),
            }
            if int(ip_proto) == 6 and tcp_dst is not None:
                match_hint["tcp_dst"] = int(tcp_dst)
            if int(ip_proto) == 17 and udp_dst is not None:
                match_hint["udp_dst"] = int(udp_dst)
            return False, match_hint, best_prio

        return True, None, None

    @staticmethod
    def install_drop_flow(datapath, parser, match, priority: int, idle_timeout: int = 60) -> None:
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=int(priority),
            match=match,
            instructions=[],
            idle_timeout=int(idle_timeout),
            hard_timeout=0,
        )
        datapath.send_msg(mod)
