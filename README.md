# Windows Management Instrumentation (WMI) Command Executor

A C++ implementation inspired by Impacket’s `wmiexec.py`, demonstrating how to execute commands remotely via Windows Management Instrumentation (WMI).

This tool supports both **username/password (NTLM)** and **Kerberos (TGT from current session)** authentication, establishes an SMB connection for output retrieval, and provides an interactive shell-like interface for executing commands.

---

## Features

* Execute arbitrary commands remotely over WMI.
* Authentication options:

  * **Username/Password (NTLM)** with explicit credentials.
  * **Kerberos** using the current session’s TGT (`klist` shows cached tickets).
* Automatic SMB connection to `ADMIN$` for retrieving command output.
* Interactive REPL (type commands, output is streamed back).
* Verbose diagnostics for debugging (`-v`).

---

## Prerequisites

* Windows OS
* Visual Studio with C++ support
* Valid credentials or a valid Kerberos TGT (e.g., via `klist`)

---

## Usage

```powershell
wmiexec.exe -t <target-host> -d <domain> [options]
```

### Options

| Option           | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `-t, --target`   | Target host (IP, NetBIOS, or FQDN)                       |
| `-d, --domain`   | Domain name                                              |
| `-u, --user`     | Username (required if not using Kerberos)                |
| `-p, --password` | Password (required if not using Kerberos)                |
| `-k, --kerberos` | Use current session Kerberos TGT (requires NetBIOS/FQDN) |
| `-v, --verbose`  | Enable verbose diagnostics                               |
| `-h, --help`     | Show help                                                |

---

### Examples

Authenticate with username and password:

```powershell
wmiexec.exe -t 192.168.1.200 -d EXAMPLE.LOCAL -u alice -p Passw0rd!
```

Authenticate with Kerberos (current TGT in memory):

```powershell
wmiexec.exe -t SRV01 -d EXAMPLE.LOCAL --kerberos
```

Verbose mode for troubleshooting:

```powershell
wmiexec.exe -t SRV01 -d EXAMPLE.LOCAL -u alice -p Passw0rd! -v
```

---

## Important Notes

* Requires administrative rights on the remote machine.
* Kerberos requires a valid TGT (`klist` to verify).
* Tested against Windows Servers.
* **Security Warning**: Output is written temporarily to `C:\Windows\Temp\output_<timestamp>.txt` on the target machine before being read back.

---

## Future Development

* Output encryption before writing to disk.
* File upload/download support over SMB.
* Better error handling and logging.

---

## Credits

* Inspired by [Impacket’s wmiexec.py](https://github.com/fortra/impacket).
* Built as a learning project for low-level COM/WMI interaction in C++.