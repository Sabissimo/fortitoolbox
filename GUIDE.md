# FortiToolbox — Guía de uso

Pensada para el operador. Cada sección, lo justo.

## Conexión
- **Connect** abre el diálogo. **Demo mode** = dispositivo simulado (para sala/
  pruebas). Real = host + usuario (read-only) + password; **Enter conecta**.
- **Account has diagnose**: actívalo si tu cuenta tiene `system-diagnostics enable`
  (salta el probe). Si no, los checks `diagnose` salen SKIPPED — puedes forzarlos
  pulsando el chip `diagnose: OFF` de la barra superior.
- **VDOMs**: si el equipo es multi-VDOM, aparece el desplegable; eliges el VDOM
  activo (default `root`). Los checks per-VDOM corren en ese; los global, en global.
- La barra superior muestra modelo / versión / **serial enmascarado** / hostname.

## Tablero y ejecución
- **Quick health** (kit rápido) · **Full sweep** (todo) · **Run all in <pestaña>** ·
  o el botón **▶** de cada check.
- Contadores arriba (FAIL/WARN/PASS/INFO): **clic = filtrar** las cards a ese estado
  en todas las pestañas; mientras el filtro está activo, un **punto del color del
  estado** marca las pestañas que contienen checks de ese tipo, para ver dónde están
  sin abrirlas una a una; "show all" limpia.
- Cada card: lámpara de estado, headline (la conclusión), métricas (el número que
  importa) y "Raw output" plegable.

## Copy for LLM
Botón **Copy for LLM**: ofusca todo el output (serials/IPs/MACs/hosts/emails →
tokens reversibles; secretos fuera) y lo copia listo para pegar en un LLM. Toggle
**mask** para mostrar los campos de secreto como `<SECRET_n>` (valor descartado).
Si el leak-check no está limpio, **bloquea la copia**.

## Report (PDF)
Botón **Report**: genera un PDF con firma del dispositivo (serial enmascarado),
barra de veredictos y todos los checks por módulo. Para adjuntar al ticket o
entregar al cliente.

## Consola SSH
Botón **Console** (panel derecho): comandos en vivo contra el equipo. Output crudo
(banner de aviso, **sin ofuscar**). Botones: Send · Ctrl-C · Kill debug · Clear ·
**Obfuscate & copy** (pasa la selección por el ofuscador). Canal dedicado: no
interfiere con los checks.

## Advanced — Debug Flow
1. Escribe el objetivo: IP, puerto y/o proto en una línea (`tcp,443,1.1.1.1`); sin
   interfaz = se usa el contexto del VDOM. Nº de paquetes (default 10).
2. **Run flow**: captura en vivo con contador y **Stop** (limpia el debug siempre).
3. Resultado: **conclusiones** arriba (p.ej. "RPF drop: ruta de vuelta…"), **pipeline**
   IN→ROUTE→POLICY→NAT→UTM→OUT (solo lo que ocurre; DROP en rojo), **stepper** por
   paquete, y Raw por paquete.
4. Botones: **Live session** (la sesión viva por tupla: NAT/offload/bytes), **Sniff
   this flow** (pre-rellena el sniffer), **Copy for LLM**.

## Advanced — Packet Sniffer
1. Filtro inteligente: `wan1 tcp 443` o `tcp,443,8.8.8.8` (sin interfaz = any).
   Max packets (default 5000, editable).
2. **Capture**: en vivo con Stop. Resumen por paquete (hora/interfaz/origen→destino/
   info), desplegable por paquete con su hex.
3. **Download .pcap** → ábrelo en Wireshark.

## Advanced — Authentication test
1. **Load servers** (se autocargan al conectar) → elige protocolo y servidor.
   RADIUS muestra el selector de **esquema** (pap/chap/mschap/mschap2).
2. Usuario + password (enmascarada, no se guarda).
3. **Test auth**: estado (OK/FAIL) + **grupos** devueltos + conclusiones. Toggle
   **fnbamd verbose** para la negociación detallada. SAML no es testeable por CLI.
