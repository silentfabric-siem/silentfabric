# Sending logs to SilentFabric

SilentFabric listens on:

| Port | Protocol | Use |
| --- | --- | --- |
| 514/udp | Syslog (RFC 5424 or 3164) | Network devices, simple Linux setups |
| 514/tcp | Syslog, newline or octet-counted framing | Linux with rsyslog, anything that supports TCP |
| 8080/tcp | HTTP `POST /api/v1/events`, JSON or NDJSON | Windows and macOS agents, scripts |

Replace `SIEM` below with the VM's address. Vendor menu names change between firmware versions, so treat the device steps as a guide.

## What gets parsed

| Source | How it arrives | `event.dataset` |
| --- | --- | --- |
| Windows event logs (Security, System, Sysmon, PowerShell) | NXLog CE, Winlogbeat/Elastic Agent JSON, or Fluent Bit `winevtlog` over HTTP | `windows.security`, `windows.sysmon`, ... |
| Linux syslog | rsyslog or syslog-ng | `syslog` (sshd, sudo, su, useradd, userdel parsed) |
| Linux journald | Fluent Bit `systemd` input or Vector, JSON over HTTP | `linux.journald` |
| macOS unified log | `log stream --style ndjson` via Vector, over HTTP | `macos.unifiedlog` |
| Ubiquiti UniFi | Syslog (firewall rule logs) or CEF (UniFi Network 9+ SIEM integration) | `unifi.firewall`, `unifi.<category>` |
| SonicWall | Syslog, default key=value format; CEF also accepted | `sonicwall.firewall` |
| Linux firewalls (iptables, UFW) | Kernel syslog lines | `linux.iptables` |
| Anything sending CEF | Syslog | `cef` |

Normalized fields include `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.transport`, `user.name`, `event.action`, `event.outcome`, `process.command_line` and `rule.name`. `log.source.ip` is the address the log was received from. Windows events also keep their native names (`EventID`, `Image`, `CommandLine`, `TargetUserName`) so [SigmaHQ](https://github.com/SigmaHQ/sigma) Windows rules work unchanged.

## Windows (NXLog Community Edition)

Install [NXLog CE](https://nxlog.co/products/nxlog-community-edition) and use this `nxlog.conf` section. Installing [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) as well gives far better process and network visibility.

```
<Extension _json>
    Module  xm_json
</Extension>

<Input eventlog>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
                <Select Path="System">*</Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
                <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
    Exec    to_json();
</Input>

<Output silentfabric>
    Module      om_http
    URL         http://SIEM:8080/api/v1/events
    ContentType application/json
</Output>

<Route r>
    Path eventlog => silentfabric
</Route>
```

## Linux (rsyslog)

Create `/etc/rsyslog.d/90-silentfabric.conf` and restart rsyslog:

```
*.* @@SIEM:514;RSYSLOG_SyslogProtocol23Format
```

`@@` sends over TCP; use a single `@` for UDP.

## macOS (Vector)

macOS keeps logs in the unified log instead of syslog. Install [Vector](https://vector.dev) and use:

```toml
[sources.macos]
type = "exec"
mode = "streaming"
command = ["/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
  "process == \"sudo\" OR process == \"sshd\" OR process == \"su\" OR subsystem == \"com.apple.securityd\""]
decoding.codec = "json"

[sinks.silentfabric]
type = "http"
inputs = ["macos"]
uri = "http://SIEM:8080/api/v1/events"
encoding.codec = "json"
framing.method = "newline_delimited"
```

Widen the predicate to collect more; the full unified log is very noisy.

## Ubiquiti UniFi

In UniFi Network, open the system or CyberSecure settings, find **Activity Logging / SIEM Server (Syslog)**, and set the server to `SIEM` port `514`. To see firewall traffic, enable logging on the firewall rules or policies you care about. UniFi Network 9 and later send CEF; older gateways send kernel firewall lines. Both are parsed.

## SonicWall

In SonicOS go to **Device > Log > Syslog**, add a syslog server `SIEM` on UDP `514`, and keep the default syslog format. Set the event categories and priority you want under **Log > Settings**.
