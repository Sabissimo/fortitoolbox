"""In-app reference: what each check detects and its verdict logic. Available
offline (no connection). Commands are read from catalog.yaml; this module adds the
human description + verdict criteria per check id, plus the interactive tools.
"""

REFERENCE = {
    # System & Health
    "version_model": ("Model, firmware version, serial, hostname and device clock.",
                      "PASS if version is 7.4/7.6/8.0; WARN if outside the supported set."),
    "resources": ("Memory usage, CPU and conserve mode.",
                  "PASS mem<88% and conserve off; WARN mem>=88%; FAIL conserve active."),
    "conserve": ("Kernel vs shared-memory (proxy/WAD) conserve mode.",
                 "PASS both off; WARN shm/proxy conserve; FAIL kernel conserve."),
    "fortiguard": ("FDS connectivity and per-module licence expiry.",
                   "PASS all healthy and FDS available; WARN a module <30d; FAIL expired or FDS down."),
    "ha": ("HA sync (config checksum) and recent role changes (history).",
           "PASS in-sync; WARN primary change in <7d; FAIL out-of-sync (checksum mismatch); INFO standalone."),
    "ntp": ("System clock synchronisation.",
            "PASS synchronised; WARN not synced (breaks certs/SAML/HA/log correlation)."),
    "crashlog": ("Recent process crashes.",
                 "PASS empty; WARN crashes >7d old; FAIL a crash in the last 7d."),
    "config_error_log": ("Config that did not fully apply.",
                         "PASS no entries; FAIL any error entry (config may not be fully applied)."),
    "certificates": ("Local certificate expiry and role (SSL-inspection / remote-gw / device).",
                     "PASS all >30d; WARN any <=30d; FAIL any expired."),
    "hw_certificate": ("Hardware / factory certificate.",
                       "PASS valid; FAIL on expired/invalid; INFO if format unknown."),
    "sensors": ("Hardware sensors: temperature, fans, PSU.",
                "PASS within range; FAIL on an alarm; INFO on VM / unsupported."),
    "faz_logging": ("Log shipping to FortiAnalyzer.",
                    "PASS connection up & registered; FAIL down; INFO if no FAZ configured."),
    # Network
    "interfaces": ("Per-NIC hardware truth (link/speed/duplex/errors) cross-checked with addressing.",
                   "WARN if an ADDRESSED port is not up + >=1000 + full-duplex, or has rx/tx errors."),
    "routing": ("Routing table sanity.",
                "PASS default route present; WARN no default route; INFO blackhole routes."),
    "dynamic_routing": ("BGP / OSPF adjacencies.",
                        "PASS all established/Full; WARN any not established; INFO none configured."),
    "sessions": ("Session table stats.",
                 "PASS normal; WARN clash or memory-tension drops > 0."),
    "interface_errors": ("rx/tx errors and drops per logical interface (incl. VLANs/tunnels).",
                         "PASS none; WARN any interface with errors/drops."),
    "arp": ("ARP table and per-interface counts.",
            "PASS all resolved; WARN incomplete entry (00:00:00:00:00:00 = L2 next-hop down)."),
    "policy_routes": ("Policy routes / SD-WAN rules installed in the kernel (override the routing table).",
                      "INFO with the count (a present proute explains traffic that ignores the FIB)."),
    # SD-WAN
    "sdwan_health": ("SD-WAN health-check SLA per member.", "WARN if any member is dead."),
    "sdwan_service": ("SD-WAN rules / service path selection.",
                      "WARN if a rule has no selected member (traffic blackholed)."),
    "sdwan_members": ("SD-WAN member interfaces.", "WARN if any member is dead."),
    "sdwan_sla_log": ("Recent SLA transitions.", "WARN if a member went down recently (flapping)."),
    # VPN
    "vpn_ipsec_summary": ("IPsec phase-2 selectors up/down.",
                          "WARN if any tunnel has selectors down/incomplete."),
    "vpn_ike_gw": ("IKE phase-1 gateways.", "WARN if any phase-1 is not established."),
    "vpn_ssl": ("Active SSL-VPN sessions.", "INFO with the connected-user count."),
    "vpn_ipsec_traffic": ("Per-SA traffic and decryption/replay errors.",
                          "WARN on tx>0 but rx=0 (asymmetry) or decryption/replay errors."),
    # Security / Policy
    "policy_hitcount": ("Dead policies (hit-count 0).", "WARN listing the dead policy indexes."),
    "webfilter_rating": ("FortiGuard web-filter rating servers.",
                         "PASS servers reachable, no loss; WARN packet loss or no servers."),
    # DNS
    "dns": ("DNS config (global), per-VDOM server readiness (dnsproxy) and live resolution (ping).",
            "FAIL no resolution or no server ready; WARN partial loss / a server not ready; PASS resolves + ready."),
    # FortiSwitch (FortiLink-managed, queried from the FortiGate)
    "fsw_managed": ("Managed FortiSwitch inventory, firmware and FortiLink link state.",
                    "PASS all Authorized/Up on the catalog target firmware (`target_fw`, default 7.6.x); WARN off-target firmware; FAIL any down/unauthorized; INFO none managed."),
    "fsw_sync": ("FortiSwitch configuration sync status.",
                 "PASS all in-sync; FAIL any sync error; INFO none managed."),
    "fsw_poe": ("Per-switch live PoE draw vs budget plus per-port faults (from `poe summary`).",
                "PASS within budget; WARN any port faulted (overload/short/denied) or any switch >=90% of budget; INFO no PoE switches."),
    # FortiAP (wireless-controller managed, queried from the FortiGate)
    "fap_managed": ("Managed FortiAP inventory and CAPWAP connection state.",
                    "PASS all Connected; WARN any Disconnected/joining; INFO none managed."),
    "fap_clients": ("Connected wireless clients (stations) and their auth state.",
                    "PASS all authenticated; WARN client(s) not authenticated; INFO no clients/APs."),
    "fap_health": ("FortiAP CAPWAP control/data tunnel to the controller.",
                   "PASS all APs have an active tunnel; WARN any AP with no tunnel (0.0.0.0); INFO none."),
    "fap_radio": ("FortiAP radio load (channel utilisation), noise floor, firmware and uptime (from `-c wtp`).",
                  "PASS radios within load; WARN any radio >=70% channel utilisation, firmware drift across APs, or an AP rebooted in the last 24h; INFO no AP-mode radios. Noise floor reported as a metric (not yet verdict-driving)."),
}

# Interactive tools (Advanced)
TOOLS_REF = [
    ("Debug Flow", ["diagnose debug flow filter addr/port/proto …",
                    "diagnose debug flow trace start <N>  (bounded, auto-cleanup)"],
     "Live packet trace per-VDOM. Smart filter, shows only what happens (policy/NAT/UTM/"
     "offload), plain-language conclusions (RPF, implicit deny…), pipeline + per-packet stepper. "
     "Companions: Live session (diagnose sys session list), Sniff this flow."),
    ("Packet Sniffer", ["diagnose sniffer packet <iface|any> '<bpf>' 6 <count> a"],
     "Live capture with Stop. Smart filter (interface optional). Per-packet summary and "
     "one-click .pcap download (Ethernet frames, opens in Wireshark)."),
    ("Authentication test", ["diagnose test authserver ldap|tacacs+ <server> <user> <pass>",
                             "diagnose test authserver radius <server> <scheme> <user> <pass>"],
     "Test LDAP/RADIUS/TACACS+ with operator credentials; highlights the matched groups. "
     "Optional fnbamd verbose. Password masked, never stored, scrubbed from output. "
     "SAML is not CLI-testable."),
]
