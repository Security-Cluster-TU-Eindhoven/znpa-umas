# znpa-umas

Zeek Network Protocol Analyzers – Modbus Unity UMAS.

`znpa-umas` is a [Zeek](https://zeek.org) package that logs Schneider Electric's
proprietary UMAS (Unified Messaging Application Services) protocol, which is carried
over Modbus/TCP as function code 90 (`0x5A`) and used by Modicon PLCs. Zeek's built-in
Modbus analyzer recognizes function code 90 as `PROGRAM_UNITY` but does not parse its
payload. This package writes every UMAS request and response, with its UMAS function
code and session key, to a new log, `modbus_umas.log`. Zeek's own `modbus.log` is not
changed.

The package is a dependency of [ICtoolS](https://github.com/Security-Cluster-TU-Eindhoven/ICtoolS), a framework
for fingerprinting ICS tools in honeypot traffic. It can also be used on its own.

## Requirements

- Zeek 4.2.0 or newer, the same minimum as ICSNPP-Modbus v1.x, which ICtoolS also
  requires (tested with Zeek 9.0)
- [zkg](https://docs.zeek.org/projects/package-manager/en/stable/) 2.10 or newer, for
  installing with the package manager
- [btest](https://github.com/zeek/btest), only for running the tests

## Installation

### With zkg

```bash
zkg install https://github.com/Security-Cluster-TU-Eindhoven/znpa-umas
```

If zkg is set up to load packages (`@load packages` in `site/local.zeek`, see the
[zkg quickstart guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)),
the package is loaded automatically. Otherwise, load it by name on the command line:

```bash
zeek -C -r capture.pcap znpa-umas
```

### Manually

Copy the `scripts` directory into Zeek's site directory and load it from
`site/local.zeek`:

```bash
git clone https://github.com/Security-Cluster-TU-Eindhoven/znpa-umas.git
cp -r znpa-umas/scripts "$(zeek-config --site_dir)/znpa-umas"
echo "@load znpa-umas" >> "$(zeek-config --site_dir)/local.zeek"
```

You can also run the scripts from a clone without installing them:

```bash
zeek -C -r znpa-umas/tests/traces/modbus_umas.pcap znpa-umas/scripts
```

### Use with ICtoolS

ICtoolS needs both this package and [CISA ICSNPP-Modbus](https://github.com/cisagov/icsnpp-modbus)
v1.x:

```bash
zkg install icsnpp-modbus --version v1.0.0
zkg install https://github.com/Security-Cluster-TU-Eindhoven/znpa-umas
zeek -C -r capture.pcap icsnpp-modbus znpa-umas
```

## The `modbus_umas.log` file

Each Modbus/TCP message with function code 90 produces one entry. Modbus requests and
responses carry different information, so both are logged. `is_orig` and
`request_response` show which one an entry is.

| Field              | Type      | Description |
| ------------------ | --------- | ----------- |
| `ts`               | `time`    | Timestamp of the message. It equals `ts` of the matching entry in `modbus.log`. |
| `uid`              | `string`  | Unique ID of the connection |
| `id`               | `conn_id` | Connection 4-tuple (addresses and ports) |
| `is_orig`          | `bool`    | `T` if the message was sent by the originator (client), `F` if sent by the responder (server) |
| `tid`              | `count`   | Modbus transaction identifier |
| `unit`             | `count`   | Modbus unit identifier |
| `func`             | `string`  | Modbus function code (always `PROGRAM_UNITY`) |
| `request_response` | `string`  | `REQUEST` or `RESPONSE` |
| `umas_func`        | `string`  | UMAS function code name, see [UMAS function codes](#umas-function-codes) |
| `session_key`      | `count`   | UMAS session key. It is non-zero in messages that need a PLC reservation, obtained with `TAKE_PLC_RESERVATION`, and `0` otherwise. |

Example (from `tests/traces/modbus_umas.pcap`):

```
#fields ts                 uid                 id.orig_h  id.orig_p  id.resp_h    id.resp_p  is_orig  tid    unit  func           request_response  umas_func             session_key
1495556089.125298  Cmn7vO2ufP7bJ4MXMg  10.1.1.175  49226      10.10.10.41  502        T        52419  0     PROGRAM_UNITY  REQUEST           TAKE_PLC_RESERVATION  0
1495556089.129959  Cmn7vO2ufP7bJ4MXMg  10.1.1.175  49226      10.10.10.41  502        F        52419  0     PROGRAM_UNITY  RESPONSE          RES_OK                0
1495556089.135780  Cmn7vO2ufP7bJ4MXMg  10.1.1.175  49226      10.10.10.41  502        T        52420  0     PROGRAM_UNITY  REQUEST           GET_PLC_STATUS        80
```

### UMAS function codes

Names follow the ["The Unity (UMAS) protocol" blog series](https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html)
and are defined in [`scripts/consts.zeek`](scripts/consts.zeek). Strategy transfers
are named from the engineering workstation's point of view: a *download* copies the
program from the workstation to the PLC, an *upload* copies it from the PLC to the
workstation. In responses, `umas_func` holds the response status (`RES_OK` or
`RES_ERR`) instead of a function code.

| Code   | Name                         | Code   | Name                         |
| ------ | ---------------------------- | ------ | ---------------------------- |
| `0x01` | `QUERY_GET_COM_INFO`         | `0x31` | `DOWNLOAD_BLOCK`             |
| `0x02` | `GET_PLC_INFO`               | `0x32` | `END_STRATEGY_DOWNLOAD`      |
| `0x03` | `READ_PROJECT_INFO`          | `0x33` | `INITIALIZE_UPLOAD`          |
| `0x04` | `GET_PLC_STATUS`             | `0x34` | `UPLOAD_BLOCK`               |
| `0x06` | `GET_MEMORY_CARD_INFO`       | `0x35` | `END_STRATEGY_UPLOAD`        |
| `0x0A` | `ECHO`                       | `0x39` | `READ_ETH_MASTER_DATA`       |
| `0x10` | `TAKE_PLC_RESERVATION`       | `0x40` | `START_TASK`                 |
| `0x11` | `RELEASE_PLC_RESERVATION`    | `0x41` | `STOP_TASK`                  |
| `0x12` | `KEEP_PLC_RESERVATION_ALIVE` | `0x50` | `CSA_REQUESTS`               |
| `0x20` | `READ_MEMORY_BLOCK`          | `0x58` | `CHECK_PLC`                  |
| `0x21` | `WRITE_MEMORY_BLOCK`         | `0x70` | `READ_IO_OBJECT`             |
| `0x22` | `READ_VARIABLES`             | `0x71` | `WRITE_IO_OBJECT`            |
| `0x23` | `WRITE_VARIABLES`            | `0x73` | `GET_STATUS_MODULE`          |
| `0x24` | `READ_COILS_REGISTERS`       | `0xFD` | `RES_ERR` (error response)   |
| `0x25` | `WRITE_COILS_REGISTERS`      | `0xFE` | `RES_OK` (success response)  |
| `0x30` | `INITIALIZE_DOWNLOAD`        |        |                              |

Other codes are logged as `unknown-<n>`, where `<n>` is the code in **decimal**. For
example, `0x99` is logged as `unknown-153`. ICtoolS depends on this format.

## How it works

Zeek's Modbus analyzer does not pass the payload of function code 90 to scripts. To read
it, the package:

1. Enables `tcp_contents` delivery for `502/tcp`. This gives scripts the reassembled TCP
   stream in both directions.
2. Splits the stream into Modbus/TCP ADUs using the MBAP length field, so that it handles
   several ADUs in one TCP segment and ADUs split across segments. It then records the
   UMAS session key and function code of each function-code-90 ADU by transaction
   identifier.
3. Writes the log entry when Zeek's analyzer raises `modbus_message` for the ADU with the
   same transaction identifier. This way, an entry is logged only for messages that Zeek
   accepts as Modbus, and its timestamp matches `modbus.log`.

## Limitations

- Only the UMAS function code and session key are logged. Function-specific payloads are
  not parsed.
- Only port `502/tcp` is monitored. If you register the Modbus analyzer on other ports,
  also add those ports to `tcp_content_delivery_ports_orig` and
  `tcp_content_delivery_ports_resp`.
- Modbus exception responses (function code `0xDA`) are not logged in `modbus_umas.log`.
  They still appear in `modbus.log`.
- After a gap in the TCP stream, the package discards its parsing state for that
  direction. UMAS messages following the gap are logged only after the stream lines up
  with an ADU boundary again.
- Sending `tcp_contents` to the script layer makes Zeek do extra work for every packet on
  port 502. This can matter on high-volume Modbus links.

## Testing

```bash
cd tests
btest -c btest.cfg
```

The tests run two traces:

- `tests/traces/modbus_umas.pcap`: a UMAS session with a Modicon M340 PLC. The
  trace has been sanitized: the workstation name, MAC addresses, project CRCs and a
  hash read from PLC memory were replaced with fake values of the same length.
- `tests/traces/umas_segmentation.pcap`: a synthetic trace with pipelined ADUs, split
  ADUs, mixed Modbus/UMAS segments and an unknown UMAS function code. It is generated by
  [`tests/scripts/gen-segmentation-trace.py`](tests/scripts/gen-segmentation-trace.py).

## Citation

If you use this package in your research, please cite the ICtoolS paper, published at
the Industrial Control System Security (ICSS) Workshop 2026, co-located with ACSAC:

```bibtex
@inproceedings{ictools,
  title     = {{ICtoolS}: Fingerprinting {ICS} Tools to Characterize Honeypot Interactions},
  author    = {Kempinski, Stash and Asanache, Victor and Lahaije, Lucas and Schlett, Kristopher and Sciancalepore, Savio and Zambon, Emmanuele and Zannone, Nicola},
  booktitle = {Industrial Control System Security Workshop (ICSS), co-located with the Annual Computer Security Applications Conference (ACSAC)},
  year      = {2026}
}
```

## License

Copyright (c) 2025-2026, Eindhoven University of Technology.

Released under the BSD 3-Clause License. See [`LICENSE.txt`](LICENSE.txt).
