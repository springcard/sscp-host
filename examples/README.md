# SSCP Host Examples

This directory contains two small command-line programs built on top of the
`sscp-host` library.

## sscp-test

`sscp-test` is a fixed test scenario. It first runs the library self-test, then
opens a reader, authenticates, reads basic reader information, scans for an NFC
card, and sends a sample APDU when a card is present.

Usage:

```bash
sscp-test [connection options]
```

Connection options:

```text
-p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)
-b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)
-a address      Reader address in hexadecimal, from 0x00 to 0x7F (default: 0x01)
-h              Show command-line help
```

Address values are hexadecimal; the `0x` prefix is optional. The authentication
key is the default library key.

Examples:

```bash
sscp-test -p COM8
sscp-test -p /dev/ttyUSB0 -b 115200 -a 01
```

Use this example as a compact integration test or as source code showing the
basic SSCP call sequence.

## sscp-tool

`sscp-tool` is an interactive command-line utility for common reader operations.
Without a command option, it opens the reader, authenticates, scans for an NFC
card, and exchanges a sample APDU when a card is present.

Usage:

```bash
sscp-tool [connection options] [command]
```

Connection options:

```text
-p serial_port  Serial port name (default: COM8 on Windows, /dev/ttyUSB0 otherwise)
-b bitrate      Connection bitrate: 9600, 38400, or 115200 (default: 38400)
-a address      Reader address in hexadecimal, from 0x00 to 0x7F (default: 0x01)
-k auth_key     Authentication key as 16 hexadecimal bytes, optionally prefixed with 0x
```

Commands:

```text
-I              Print reader information and exit
-U c d b        Call SSCP_Outputs(c, d, b) and exit
-R rgb d b      Call SSCP_OutputsRGB(rgb, d, b) and exit
-A address      Set the reader address and exit
-B bitrate      Set the reader bitrate: 9600, 19200, 38400, 57600, or 115200 and exit
-K new_key      Set the reader key and exit
-h              Show command-line help
```

Only one command option may be specified at a time. Address, key, and RGB color
values are hexadecimal; the `0x` prefix is optional. Output duration values
accept decimal or `0x`-prefixed hexadecimal input. The `-B` command connects to
the reader with the bitrate specified by `-b`, then asks the reader to switch to
the new bitrate.

Examples:

```bash
sscp-tool -p COM8 -I
sscp-tool -p COM8 -R 2244FF 255 0
sscp-tool -p /dev/ttyUSB0 -b 115200 -a 01
sscp-tool -p COM8 -b 38400 -B 115200
sscp-tool -k 00112233445566778899AABBCCDDEEFF -A 02
```
