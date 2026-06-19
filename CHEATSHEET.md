# FortiToolbox — Cheat-sheet de comandos

Las líneas de diagnóstico exactas que ejecuta cada check, por si necesitas correrlas
a mano. En equipos **multi-VDOM**, los de scope `vdom` van envueltos en
`config vdom → edit <vdom> → … → end`; los `global` en `config global → … → end`.
Enumerar VDOMs: `diagnose sys vd list` (desde global).

`[diag]` = requiere `system-diagnostics enable` en el accprofile.

## System & Health
| Check | Comando | Detecta |
|---|---|---|
| Versión & modelo | `get system status` | modelo/versión/serial/hostname/reloj |
| Recursos & conserve | `get system performance status` | memoria, CPU, conserve |
| Conserve (kernel+shm) `[diag]` | `diagnose hardware sysinfo conserve` · `diagnose hardware sysinfo shm` | kernel vs proxy/shm conserve |
| FortiGuard `[diag]` | `get system fortiguard` · `diagnose autoupdate versions` | FDS, licencias/caducidad por módulo |
| HA `[diag]` | `get system ha status` · `diagnose sys ha checksum cluster` · `diagnose sys ha history read` | out-of-sync, failovers recientes |
| NTP `[diag]` | `diagnose sys ntp status` | sincronización de reloj |
| Crashlog `[diag]` | `diagnose debug crashlog read` | crashes recientes |
| Config error log `[diag]` | `diagnose debug config-error-log read` | config no aplicada del todo |
| Certificados (per-VDOM) | `get vpn certificate local detail` | caducidad <30d, cadena |
| Hardware/factory cert `[diag]` | `diagnose hardware certificate` | cert de hardware |
| Sensores | `execute sensor list` | temperatura/ventilador/PSU |
| FortiAnalyzer | `execute log fortianalyzer test-connectivity` | logging a FAZ |

## Network
| Check | Comando | Detecta |
|---|---|---|
| Interfaces (NIC) | `get system interface physical` (+ `diagnose hardware deviceinfo nic <port>` por puerto) | direccionados deben ir up+1000+full |
| Routing | `get router info routing-table all` | default route, blackhole |
| Dynamic routing | `get router info bgp summary` · `get router info ospf neighbor` | adyacencias BGP/OSPF |
| Sesiones `[diag]` | `diagnose sys session full-stat` | conteo, setup rate, clash, conserve |
| Errores de interfaz `[diag]` | `diagnose netlink interface list` (contexto management, sin wrap) | errores/drops rx/tx |
| ARP | `get system arp` | next-hop sin resolver |
| Policy routes `[diag]` | `diagnose firewall proute list` | rutas/SD-WAN que anulan la tabla |

## SD-WAN `[diag]`
| Check | Comando |
|---|---|
| Health-check | `diagnose sys sdwan health-check` |
| Reglas / path | `diagnose sys sdwan service4` |
| Miembros | `diagnose sys sdwan member` |
| SLA log (flaps) | `diagnose sys sdwan sla-log` |

## VPN
| Check | Comando |
|---|---|
| IPsec resumen | `get vpn ipsec tunnel summary` |
| IKE phase-1 `[diag]` | `diagnose vpn ike gateway list` |
| SSL-VPN | `get vpn ssl monitor` |
| IPsec tráfico/SA `[diag]` | `diagnose vpn tunnel list` |

## Security / Policy `[diag]`
| Check | Comando |
|---|---|
| Políticas muertas | `diagnose firewall iprope show 100004 0` |
| Web-filter rating | `diagnose debug rating` |

## DNS
| Check | Comando | Scope |
|---|---|---|
| DNS config | `get system dns` | global |
| Readiness servidores | `diagnose test application dnsproxy 3` | **global** (saca el detalle por-VDOM dentro) |
| Resolución | `execute ping update.fortiguard.net` | vdom |

## FortiSwitch (FortiLink) `vdom`
Consultados **desde el FortiGate** vía `switch-controller` (sin transporte aparte).
| Check | Comando | Detecta |
|---|---|---|
| Inventario & link | `execute switch-controller get-conn-status` | switches autorizados/up; firmware fuera del objetivo (`target_fw`, def. 7.6.x) |
| Sync de config | `execute switch-controller get-sync-status all` | config sin sincronizar |
| PoE `[diag]` | `diagnose switch-controller switch-info poe summary` | consumo vs presupuesto + puertos en fallo (overload/short/denied) |

## FortiAP (wireless-controller) `vdom` `[diag]`
Consultados **desde el FortiGate** vía `wireless-controller` (sin transporte aparte).
| Check | Comando | Detecta |
|---|---|---|
| Inventario & CAPWAP | `diagnose wireless-controller wlac -c wtp` | APs gestionados + estado de conexión |
| Clientes (stations) | `diagnose wireless-controller wlac -c sta` | estado de auth (sin RSSI; eso va en `-d sta`) |
| Túnel CAPWAP | `diagnose wireless-controller wlac -d wtp` | túnel control/datos activo (endpoint ≠ 0.0.0.0) |
| Radio / ruido / firmware | `diagnose wireless-controller wlac -c wtp` | utilización de canal (pico), noise floor, firmware, uptime (mismo dump que Inventario) |

## Interactivas (Advanced)

**Debug Flow** (per-VDOM, acotado, con limpieza garantizada):
```
diagnose debug reset
diagnose debug flow filter addr <IP> / port <PORT> / proto <N>
diagnose debug flow show function-name enable
diagnose debug flow show iprope enable
diagnose debug flow trace start <N>
diagnose debug enable
  ... [captura] ...
diagnose debug flow trace stop
diagnose debug disable ; diagnose debug flow filter clear ; diagnose debug reset
```

**Packet Sniffer** (verbosity 6 = trama completa para .pcap):
```
diagnose sniffer packet <iface|any> '<bpf>' 6 <count> a
# Stop = Ctrl-C
```

**Authentication test:**
```
diagnose test authserver ldap    <server> <user> <pass>
diagnose test authserver tacacs+ <server> <user> <pass>
diagnose test authserver radius  <server> <pap|chap|mschap|mschap2> <user> <pass>
# Verbose: diagnose debug application fnbamd -1 ; diagnose debug enable
```

**Acompañantes útiles:**
```
diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <iface> policy   # qué política matchea sin tráfico
diagnose sys session filter dst <ip> ; diagnose sys session list                      # sesión viva por tupla
```
