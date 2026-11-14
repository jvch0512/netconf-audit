# netconf-audit

Network device configs are full of the same avoidable mistakes: telnet on the VTY lines, reversible passwords, default SNMP communities, a plain HTTP management server. netconf-audit reads IOS style configuration files and reports them with the line number and a fix, so a review of a whole estate takes minutes. It only reads the text of the file, it never connects to a device.

**Live demo:** https://jvch0512.github.io/netconf-audit/ (Synthetic configs for two invented devices.)

Tcl 8.6 (tclsh), standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make test
./bin/netconf-audit examples/configs
./bin/netconf-audit edge-rtr1.cfg --tsv
./bin/netconf-audit ./configs --fail-on high     # exit 1 in CI
```

Pass a config file or a directory (`.cfg`, `.conf`, `.txt`).

| Rule | Severity | What it catches |
|---|---|---|
| NC001 | high | telnet or all protocols allowed on VTY lines |
| NC002 | high | `enable password` (reversible or cleartext) instead of `enable secret` |
| NC003 | high | SNMP community `public` or `private`, or any read-write community |
| NC004 | high | local `username ... password` (cleartext or type 7) |
| NC005 | high | well-known default line password (cisco, admin, password, 1234) |
| NC006 | medium | MD5 (type 5) secrets: use scrypt (type 9) where supported |
| NC007 | medium | `ip http server` enabled |
| NC008 | medium | VTY lines without `access-class` |
| NC009 | medium | no remote syslog (`logging host`) |
| NC010 | medium | SSH version 2 not enforced |
| NC011 | medium | `service password-encryption` missing while line passwords exist |
| NC012 | low | no NTP server, no login banner, source routing not disabled |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It understands IOS style syntax (indented children under `line` and `interface`). Other vendors need other rules.
- It judges the text only. A feature turned off elsewhere (an ACL on the line, a management VRF) is not seen.
- Defaults depend on the software version. Rules that rely on a missing line (NC009, NC010, NC012) are advice, check them against the platform.
- Secrets in configs are never printed: findings show the line number and the kind, not the value.

## Where it fits

Network security reviews and hardening baselines: a repeatable first pass on router and switch configs for audits, mergers and managed-service onboarding.

## Tests

```bash
make test    # 51 tcltest cases
```

MIT.
