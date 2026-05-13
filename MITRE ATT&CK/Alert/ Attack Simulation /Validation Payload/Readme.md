

# 🧹 Automated Cleanup & Environment Reset

The framework includes a dedicated cleanup phase designed to reduce leftover lab artifacts after execution.

This cleanup stage helps restore the testing environment by terminating spawned processes, removing temporary files, and resetting portions of the networking state.

---

# 📌 Cleanup Behaviors

## 🔪 Process Termination

The script attempts to terminate tooling and background jobs launched during execution.

### 📦 Processes Targeted

- `bettercap`
- `Responder`
- `hping3`
- `hydra`
- `socat`
- `arpspoof`
- `crunch`
- `netcat`
- `ping -f`

### 📌 Example Logic

```bash
pkill -f bettercap
pkill -f responder
pkill -f hping3
```

---

# 🗑️ Temporary File Removal

The framework removes generated artifacts including:

- temporary logs
- packet captures
- downloaded test files
- generated text files
- temporary scan outputs

### 📌 Examples

```bash
rm -f discovery.txt
rm -f *.pcap
rm -f *.log
rm -f *.tmp
```

---

# 🌐 Socket & Listener Cleanup

Temporary listeners and sockets created during simulation are terminated.

### 📌 Example

```bash
fuser -k 8080/tcp
```

---

# ♻️ Network Reset Behavior

The script attempts to reset portions of the networking state after simulation.

### 📌 Example

```bash
systemctl restart networking
```

---

# 🛑 Optional Service Shutdown

Services started for telemetry generation may be stopped during cleanup.

### 📌 Services

- `snmpd`
- `smbd`

---

# 🧽 ELF Artifact Removal

The framework attempts to locate and remove the generated ELF payload from the filesystem.

### 📌 Example Logic

```bash
find / -type f -executable -name "network.elf"
```

If found, the payload is deleted automatically.

---

# ⚠️ Important Notes

The cleanup phase is intended to:

- reduce leftover lab artifacts
- simplify repeated testing
- avoid lingering network tooling
- restore temporary lab state

However, cleanup is not guaranteed to fully restore the system to its original condition.

Some actions may still leave:

- shell history artifacts
- package installation logs
- service logs
- IDS/IPS alerts
- SIEM telemetry
- audit events
- system journal entries

---

# 🧪 Purpose of the Cleanup Stage

The cleanup phase exists to support:

- 🛡️ Detection engineering labs
- 🔬 Repeatable testing workflows
- 📊 SOC validation exercises
- 🧪 Telemetry generation experiments
- 💻 Disposable VM environments

It is not intended as stealth or anti-forensics functionality.
