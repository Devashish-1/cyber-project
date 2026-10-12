# Hardened Metasploit check runtime

This derived image pins the official Metasploit Framework image, removes the
Ruby file capabilities, and runs as non-root UID/GID 65532.

The platform may use this runtime only for a future evidence-gated `check`
operation. The control plane must select a reviewed module from a fixed CVE to
module map after matching prior target evidence. Operators cannot submit raw
resource scripts, module names, commands, payloads, sessions, or datastore
options.

Required runtime controls are a read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, bounded CPU/memory/PIDs, an
ephemeral private home directory, exact target scope, and one explicit
extended-active approval.

Exploit execution, payload generation, handlers, sessions, credential attacks,
persistence, evasion, post-exploitation, routing, and pivoting remain disabled.

The default command prints the framework version and exits; it performs no
