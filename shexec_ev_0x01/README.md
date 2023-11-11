# shexec_ev_0x01

- msfvenom generated shellcode [RC4 encrypted for static analysis evasion]
- no "legit" process injection, just a custom loader, own memory space and usual ``VirtualAlloc``->``CreateThread``->``WaitForSingleObject`` calls
- used ``reverse_tcp_rc4 payload`` [otherwise EDR triggers]

No AV/EDR detection on Windows 11 22H2 Enterprise edition.