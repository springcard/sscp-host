# sscp-host

**sscp-host** is a lightweight and portable C library designed for use in hosts (clients) communicating with NFC Readers that support the **SPAC SSCPv2** protocol in **transparent (coupler) mode**.

This library handles the framing and communication logic necessary to exchange APDU or other data with a smartcard via a coupler, leveraging the SSCP (Smart Secure Communication Protocol) version 2 as specified by the SPAC (Secure Protocol Alliance for Couplers).

## Features

- Transparent / coupler-mode SSCPv2 support  
- Designed for host (client) applications interacting with access control readers 
- Lightweight, no external dependencies beyond standard C libraries  
- Tested on Linux X64, Linux ARM64 (Raspberry) and Windows
- Easy to integrate into test tools or production software
- MIT License — free to use, modify, and distribute

## Getting Started

### Prerequisites

- C99-compatible compiler
- Reader that supports **SSCPv2 transparent mode**
- Serial or USB access to the reader (depending on your hardware)

### Build

```bash
git clone https://github.com/springcard/sscp-host.git
cd sscp-host
mkdir build
cd build
cmake ..
make
```

Alternatively, you can include the source files in your own project.

## Documentation

- [Protocol Specification (SSCPv2)](https://spac-alliance.org/protocols/sscp/)

## License

This project is licensed under the [MIT License](LICENSE).

This open-source project is provided as-is, without support or maintenance.
Developers and implementers are encouraged to use it responsibly and at their own risk.

---

**SPAC** is a trademark of the Secure Protocol Alliance for Couplers.  
**SpringCard** is a member of SPAC, but this project is not endorsed not promoted by SPAC.

