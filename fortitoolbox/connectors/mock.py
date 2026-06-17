"""Simulated FortiGate. Returns realistic canned output so the full flow can be
demoed without a live device. Outputs are seeded with intentional findings
(an expiring cert, a dead policy, an unsynced clock, a down interface, a missing
default route) so the verdict board shows a real PASS/WARN/FAIL mix.
"""
from __future__ import annotations

import datetime as _dt

from .base import Connector, DeviceInfo

_FIXTURES = {
    "get system status": """Version: FortiGate-100F v7.6.2 build1234 (GA)
Security Level: 1
Firmware Signature: certified
Serial-Number: FG100FTK20098765
BIOS version: 05000010
System Part-Number: P12345-06
Hostname: FW-EDGE-MAD-01
Operation Mode: NAT
Current HA mode: a-p, master
Cluster uptime: 41 days 6:12:55
Current Time: Tue Jun  9 09:14:02 2026
""",
    "get system performance status": """CPU states: 7% user 4% system 0% nice 88% idle 0% iowait 0% irq 1% softirq
CPU0 states: 8% user 5% system 0% nice 87% idle
Memory: 3998012k total, 3210456k used (80.3%), 612345k free, conserve mode: off
Average network usage: 142 / 168 kbps in 1 minute
Average sessions: 18422 sessions in 1 minute
Average session setup rate: 312 sessions per second in last 1 minute
Virus caught: 0 total in 1 minute
IPS attacks blocked: 4 total in 1 minute
Uptime: 41 days, 6 hours, 12 minutes
""",
    "get system fortiguard": """fortiguard-anycast: enable
protocol: https
port: 443
service-account-id: noc@example-corp.com
load-balance-servers: 1
antispam-cache: enable
webfilter-cache: enable
""",
    "diagnose autoupdate versions": """AV Engine
---------
Version: 7.00345 Contract Expiry Date: Mon 2027-03-01
Last Updated: Mon 2026-06-09  via scheduled update

Virus Definitions
-----------------
Version: 92.06789 Contract Expiry Date: Mon 2027-03-01
Last Updated: Mon 2026-06-09

IPS Attack Engine
-----------------
Version: 7.00345 Contract Expiry Date: Sun 2026-06-21
Last Updated: Sun 2026-06-08

Web Filtering
-------------
Version: 1.00 Contract Expiry Date: expired
FDS Connection: available
""",
    "diagnose sys ha checksum cluster": """================== FG100FTK20098765 ==================
is_manage_master()=1, is_root_master()=1
debugzone
global: a1 b2 c3 d4 ...
root:   e5 f6 a7 b8 ...
checksum
global: a1 b2 c3 d4 ...
root:   e5 f6 a7 b8 ...
================== FG100FTK20012340 ==================
is_manage_master()=0, is_root_master()=0
debugzone
global: a1 b2 c3 d4 ...
root:   99 00 11 22 ...
checksum
global: a1 b2 c3 d4 ...
root:   99 00 11 22 ...
""",
    "get system ha status": """HA Health Status: WARNING
Model: FortiGate-100F
Mode: HA A-P
Cluster Uptime: 41 days 06:12:55
Master selected using: <priority>
Configuration Status:
    FG100FTK20098765(updated 1 seconds ago): in-sync
    FG100FTK20012340(updated 3 seconds ago): out-of-sync
""",
    "diagnose sys ha history read": """HA event history (most recent first):
<2026-06-05 03:12:44> vcluster 1: FG100FTK20098765 is selected as the primary, reason: member up
<2026-06-05 03:12:39> vcluster 1: FG100FTK20098765 detected member FG100FTK20012340 lost heartbeat
<2026-04-29 02:00:11> vcluster 1: FG100FTK20098765 is selected as the primary, reason: initial boot
""",
    "diagnose sys ntp status": """synchronized: no, ntpsync: enabled, server-mode: disabled
ipv4 server(pool.ntp.org) 91.189.94.4 -- reachable(0xff)  selected
    no valid packets received, offset unknown
""",
    "diagnose sys logdisk usage": """Total HD usage: 12345MB/61000MB
Total HD logging space: 54000MB
Used HD logging space: 9123MB (16.9%)
""",
    "diagnose debug crashlog read": """1: 2026-05-12 03:14:21 the killed daemon is /bin/wad: status=0x0
2: 2026-05-12 03:14:21 application wad pid 1234 exit ...
""",
    "diagnose debug config-error-log read": "",
    "get vpn certificate local detail": """== Local certificates ==
Name: Fortinet_Factory
  Subject: C=US, ST=California, CN=FG100FTK20098765
  Issuer:  CN=fortinet-subca2001
  Valid from: 2021-01-01 00:00:00 GMT
  Valid to:   2049-01-01 00:00:00 GMT
Name: SSL-Inspection-CA
  Subject: CN=Corp-DeepInspect-CA, O=Example Corp
  Issuer:  CN=Corp-Root-CA
  Valid from: 2024-06-01 00:00:00 GMT
  Valid to:   2026-06-21 00:00:00 GMT
Name: vpn-portal-gw
  Subject: CN=vpn.example-corp.com
  Issuer:  CN=R3, O=Let's Encrypt
  Valid from: 2026-04-10 00:00:00 GMT
  Valid to:   2026-07-09 00:00:00 GMT
""",
    "get system interface physical": """== [ port1 ]
        name: port1   mode: static  ip: 203.0.113.2 255.255.255.248  status: up  speed: 1000Mbps  link: up
== [ port2 ]
        name: port2   mode: static  ip: 10.10.10.1 255.255.255.0   status: up  speed: 1000Mbps  link: up
== [ port3 ]
        name: port3   mode: dhcp    ip: 0.0.0.0 0.0.0.0            status: up  speed: n/a       link: down
== [ port4 ]
        name: port4   mode: static  ip: 10.20.0.1 255.255.255.0    status: down speed: n/a       link: down
""",
    "get router info routing-table all": """Codes: K - kernel, C - connected, S - static, B - BGP, O - OSPF
S*    0.0.0.0/0 [10/0] via 203.0.113.1, port1
C     10.10.10.0/24 is directly connected, port2
C     10.20.0.0/24 is directly connected, port4
B     172.16.0.0/16 [20/0] via 10.10.10.250, port2, 2d04h12m
S     192.0.2.0/24 [10/0] is a summary, Null0
""",
    "get router info bgp summary": """BGP router identifier 10.10.10.1, local AS number 65010
Neighbor        V    AS  MsgRcv  MsgSent  Up/Down   State/PfxRcd
10.10.10.250    4 65001  120345   119876  2d04h12m  214
198.51.100.7    4 65020       0        0  never     Active
""",
    "get router info ospf neighbor": """OSPF process 0:
Neighbor ID     Pri  State        Dead Time  Address       Interface
10.10.10.5        1  Full/DR      00:00:38   10.10.10.5    port2
10.20.0.9         1  ExStart/DR   00:00:31   10.20.0.9     port4
""",
    "diagnose sys sdwan health-check": """Health Check(FGD_DNS):
 Seq(1 port1): state(alive), latency(8.412), jitter(0.531), packet loss(0.000%)
Health Check(ISP2_PING):
 Seq(2 port2): state(dead), latency(0.000), jitter(0.000), packet loss(100.000%)
""",
    "diagnose sys session full-stat": """misc info:  session_count=18422 setup_rate=312 exp_count=0 clash=0
        memory_tension_drop=0 ephemeral=0/131072 removeable=0
npu_session_count=15012
total_session=18422
""",
    "diagnose firewall iprope show 100004 0": """idx=1 pkts/bytes=204812/30551222 hit count:18422 first:2026-04-29 last:2026-06-09
idx=2 pkts/bytes=11920/9912233 hit count:3847 first:2026-05-01 last:2026-06-09
idx=7 pkts/bytes=0/0 hit count:0 first: last:
idx=12 pkts/bytes=0/0 hit count:0 first: last:
idx=15 pkts/bytes=99201/120932 hit count:9610 first:2026-04-30 last:2026-06-09
""",
    "diagnose debug rating": """Locale       : english
Service      : Web-filter
Status       : Enable
License      : Contract
-=- Server List (Tue Jun  9 09:14:30 2026) -=-
IP              Weight   RTT  Flags   TZ    Packets  Curr Lost  Total Lost
173.243.138.196    0      12   DI       -8    8842      0          0
208.91.112.194     5      31           -5    1203      0          2
""",
    "get system dns": """primary: 96.45.45.45
secondary: 96.45.46.46
dns-over-tls: disable
domain: example-corp.com
""",
    "execute ping update.fortiguard.net": """PING update.fortiguard.net (12.34.56.78): 56 data bytes
64 bytes from 12.34.56.78: icmp_seq=0 ttl=54 time=18.2 ms
64 bytes from 12.34.56.78: icmp_seq=1 ttl=54 time=17.9 ms
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max = 17.9/18.1/18.4 ms
""",
    "diagnose sys top 1 1": "Run Time: 41 days, 6 hours\n0 wad 1234 R 2.1 3.0\n",
    # NOTE: command + output format ASSUMED -- pending Héctor confirmation.
    "diagnose sys sdwan service4": """Service(1): Address Mode(IPV4) flags=0x200 Gen(1), TOS(0x0/0x0), Protocol(0: 1->65535), Mode(sla), sla-compare-order
  Members(2):
    1: Seq_num(1 port1), alive, sla(0x1), gid(0), cfg_order(0), cost(0), selected
    2: Seq_num(2 port2), alive, sla(0x1), gid(0), cfg_order(1), cost(0), selected
  Dst address(1): 10.100.21.0-10.100.21.255
Service(2): Address Mode(IPV4) flags=0x0 Gen(2), TOS(0x0/0x0), Protocol(0: 1->65535), Mode(sla), sla-compare-order
  Members(1):
    1: Seq_num(2 port2), dead, sla(0x0), gid(0), cfg_order(0), cost(0)
  Dst address(1): 0.0.0.0-255.255.255.255
""",
    "diagnose sys sdwan member": """Member(1): interface(port1), gateway(203.0.113.1), priority(0), weight(0), status(alive)
Member(2): interface(port2), gateway(198.51.100.1), priority(0), weight(0), status(dead)
""",
    "diagnose sys sdwan sla-log": """SLA(FGD_DNS) Seq(1 port1): timestamp 2026-06-09 09:10:01 -> alive
SLA(ISP2_PING) Seq(2 port2): timestamp 2026-06-09 08:55:12 -> dead
SLA(ISP2_PING) Seq(2 port2): timestamp 2026-06-09 08:54:02 -> alive
""",
    "get vpn ipsec tunnel summary": """'HQ-to-Branch1' 198.51.100.10:0  selectors(total,up): 1/1  rx(pkt,err): 104320/0  tx(pkt,err): 98213/0
'HQ-to-Branch2' 198.51.100.20:0  selectors(total,up): 1/0  rx(pkt,err): 0/0  tx(pkt,err): 1203/7
'RA-dialup' 0.0.0.0:0  selectors(total,up): 3/3  rx(pkt,err): 55012/0  tx(pkt,err): 48771/0
""",
    "diagnose vpn ike gateway list": """vd: root/0
name: HQ-to-Branch1
version: 2
serial: 1
  state: established
  established: 6 days ago
name: HQ-to-Branch2
version: 2
serial: 2
  state: connecting
  established: n/a
""",
    "get vpn ssl monitor": """SSL-VPN Login Users:
 Index   User      Group     Auth Type   Timeout   Auth-Logon
 0       jdoe      sslgrp    1(1)        259200    -
 1       acontrol  sslgrp    1(1)        259200    -
SSL-VPN sessions:
 Index   User      Source IP        Duration
 0       jdoe      203.0.113.55     01:24:10
 1       acontrol  203.0.113.61     00:12:44
""",
    "diagnose hardware certificate": """Factory certificate:
  Subject : CN=FG100FTK20098765, O=Fortinet
  Issuer  : CN=fortinet-subca2001
  Valid to: 2049-01-01
  Status  : valid
TPM: present, key sealed
""",
    "diagnose hardware deviceinfo nic port1": """Description :Host Interface
Admin           :up
link_status     :Up
Speed           :1000
Duplex          :Full
Rx_Packets      :104832212
Rx_Errors       :0
Tx_Packets      :98221190
Tx_Errors       :0
""",
    "diagnose hardware deviceinfo nic port2": """Description :Host Interface
Admin           :up
link_status     :Up
Speed           :1000
Duplex          :Half
Rx_Packets      :552210
Rx_Errors       :318
Tx_Packets      :498110
Tx_Errors       :12
""",
    "diagnose hardware deviceinfo nic port3": """Description :Host Interface
Admin           :up
link_status     :Down
Speed           :0
Duplex          :Unknown
Rx_Packets      :0
Rx_Errors       :0
Tx_Packets      :0
Tx_Errors       :0
""",
    "diagnose hardware deviceinfo nic port4": """Description :Host Interface
Admin           :down
link_status     :Down
Speed           :0
Duplex          :Unknown
Rx_Packets      :0
Rx_Errors       :0
Tx_Packets      :0
Tx_Errors       :0
""",
    "diagnose test application dnsproxy 3": """worker idx: 0
VDOM: root, index=0, is primary, vdom dns is enabled, pip-0.0.0.0 dns_log=1
dns64 is disabled
DNS servers:
8.8.8.8:53 vrf=0 tz=0 encrypt=none req=137290 to=95 res=137149 rt=1 ready=1 timer=0 probe=0 failure=0 last_failed=0
8.8.8.8:853 vrf=0 tz=0 encrypt=dot req=69637 to=69626 res=10 rt=204 ready=1 timer=0 probe=0 failure=15896 last_failed=418
96.45.46.46:53 vrf=0 tz=0 encrypt=none req=77099 to=88 res=76984 rt=2 ready=1 timer=0 probe=0 failure=0 last_failed=0
96.45.46.46:853 vrf=0 tz=0 encrypt=dot req=284917 to=1172 res=283714 rt=2 ready=1 timer=0 probe=0 failure=0 last_failed=0
SDNS servers:
ALT servers:
""",
    "diagnose hardware sysinfo conserve": """memory conserve mode: off
total RAM: 3998 MB
memory used: 3210 MB 80%
memory freeable: 240 MB 6%
memory used threshold red: 88%
memory used threshold green: 82%
""",
    "diagnose hardware sysinfo shm": """SHM counter: 12
SHM allocated: 100 MB
SHM total: 2048 MB
SHM fs total: 2097152
SHM fs free: 1900000
conserve mode: 0
""",
    "execute sensor list": """Temperature  CPU0       45 C   (alarm:85)
Temperature  SYS        38 C   (alarm:80)
Fan          FAN1     4200 RPM
PSU          PSU1       OK
""",
    "execute log fortianalyzer test-connectivity": """FortiAnalyzer Host Name: FAZ-MAD-01
Connection: allow
Registration: registered
Adom: root
Connection status: UP
Disk usage: 12%
""",
    "diagnose netlink interface list": """if=port1 family=00 type=1 index=3 mtu=1500 link=1 master=0 state=start
    stat: rxp=104832212 txp=98221190 rxe=0 txe=0 rxd=0 txd=0
if=port2 family=00 type=1 index=4 mtu=1500 link=1 master=0 state=start
    stat: rxp=552210 txp=498110 rxe=318 txe=12 rxd=44 txd=0
if=port4 family=00 type=1 index=6 mtu=1500 link=0 master=0 state=down
    stat: rxp=0 txp=0 rxe=0 txe=0 rxd=0 txd=0
""",
    "get system arp": """Address           Age(min)   Hardware Addr      Interface
203.0.113.1       0          00:11:22:33:44:01  port1
10.10.10.250      2          00:11:22:33:44:02  port2
10.20.0.9         0          00:00:00:00:00:00  port4
""",
    "diagnose firewall proute list": """list route policy info(vf=root):
id=2131689472(0x7f060000) vwl_service=1(ISP1) flags=0x0 protocol=0 oif=3(port1)
source(1): 10.10.10.0-10.10.10.255
destination(1): 0.0.0.0-255.255.255.255
""",
    "diagnose vpn tunnel list": """list all ipsec tunnel in vd 0
name=HQ-to-Branch1 ver=2 serial=1 198.51.100.10:500->203.0.113.2:500
  bytes(tx/rx)=98213000/104320000 packets(tx/rx)=98213/104320
  dec: pkts=104320 errors=0 replay=0
name=HQ-to-Branch2 ver=2 serial=2 198.51.100.20:500->203.0.113.2:500
  bytes(tx/rx)=1203000/0 packets(tx/rx)=1203/0
  dec: pkts=0 errors=0 replay=0
""",
    "get user ldap": """== [ corp-ldap ]
name        : corp-ldap
server      : 10.20.0.10
== [ dmz-ldap ]
name        : dmz-ldap
server      : 10.30.0.10
""",
    "get user radius": """== [ corp-radius ]
name        : corp-radius
server      : 10.20.0.20
""",
    "get user tacacs+": "",
    "diagnose sys vd list": """list virtual firewall info:
name=root/root index=0 enabled fib_ver=12 use=63 rt_num=8
name=customer-a/customer-a index=1 enabled fib_ver=5 use=20 rt_num=4
name=customer-b/customer-b index=2 enabled fib_ver=3 use=12 rt_num=3
""",
}


class MockConnector(Connector):
    name = "mock"

    def __init__(self, version: str = "7.6", vdom: bool = False):
        self._version = version
        self._vdom = vdom

    def connect(self) -> None:
        pass

    def close(self) -> None:
        pass

    def run(self, command: str, scope=None, vdom=None) -> str:
        cmd = command.strip()
        if cmd.startswith("diagnose firewall iprope lookup"):
            return ("gnum=100004 policy match:\n"
                    "  iprope_in_check: matched policy-7 (action accept)\n"
                    "  best matched policy id=7\n")
        if cmd in _FIXTURES:
            return _FIXTURES[cmd]
        # tolerate {fqdn}-templated ping
        for key in _FIXTURES:
            if cmd.split()[0:2] == key.split()[0:2] and key.startswith("execute ping"):
                return _FIXTURES[key]
        return f"(mock) no fixture for: {cmd}\n"

    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            model="FortiGate-100F", version="7.6",
            full_version="v7.6.2 build1234", serial="FG100FTK20098765",
            hostname="FW-EDGE-MAD-01", sysdiag_enabled=True,
            now=_dt.datetime(2026, 6, 9, 9, 14, 2),  # matches the fixture clock
            vdom_mode=self._vdom, vdoms=[], mgmt_vdom="root",
        )
