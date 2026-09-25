# ChipVPN
A lightweight, high-performance VPN server written entirely in C, built from scratch to achieve 100% protocol interoperability with official WireGuard® clients.

ChipVPN implements the complete WireGuard state machine, successfully negotiating secure tunnels with strict, production-grade clients (including the official iOS app) by manually handling the underlying Noise protocol, cryptographic derivations, and network byte-order constraints.

## Core Features
Full WireGuard Interoperability: Communicates seamlessly with official WireGuard clients without requiring any client-side modifications.

Noise_IKpsk2 Protocol: Implements the exact 1-RTT handshake (e, ee, se, psk) required to establish a secure tunnel.

Perfect Forward Secrecy (PFS): Supports continuous, seamless rekeying every 2 minutes without dropping active IP packets.

Stealth & DDoS Protection: Validates MAC1 on all incoming packets using Keyed-BLAKE2s, instantly dropping unauthenticated traffic or network scanners without executing expensive cryptographic operations.

Seamless Roaming: Dynamically updates peer endpoints upon receiving valid Data/Keepalive packets, allowing clients to switch between Wi-Fi and Cellular networks seamlessly.

## Cryptographic Stack
ChipVPN uses modern, state-of-the-art cryptographic primitives mapped exactly to the WireGuard whitepaper:

Key Exchange: X25519 (Curve25519) with strict mathematical clamping and all-zero point rejection.

Encryption (AEAD): ChaCha20-Poly1305 for both handshake payloads and IP data packets.

Hashing & MACs: BLAKE2s (RFC 7693) for transcript hashing, MAC1/MAC2 generation, and key derivation.

Key Derivation (KDF): HKDF (RFC 5869) for chaining keys (C), transcript hashes (H), and extracting symmetric transport keys (T_i, T_r).

Timestamping: TAI64N format with strict monotonic validation to prevent packet replay attacks.

## Protocol Implementation Details
Building a WireGuard clone requires strict adherence to network and cryptographic constraints. ChipVPN successfully handles:

Strict Little-Endianness: Bypasses standard htonl/ntohl TCP/IP network byte order, processing all session IDs and 64-bit nonces natively in Little-Endian to match the WireGuard specification.

Variable-Length Data Packets: Dynamically calculates ciphertext sizes to locate the appended 16-byte Poly1305 MAC for in-place decryption of Type 4 packets.

Zero-Byte Keepalives: Correctly processes 32-byte network packets containing a 0-byte ChaCha20 payload to maintain active NAT traversal.

Cryptographic Transcript Syncing: Maintains a flawless running hash (H) of all plaintext and ciphertext exchanges to authenticate the handshake via the final msg.empty AEAD tag.

Getting Started
(Assuming a standard UNIX-like environment)

Bash
# Build the VPN server
make

# Run the server with your configuration file (requires root for TUN/TAP interface creation)
sudo ./chipvpn config2.txt
Server Configuration
Ensure your server is configured with a valid Curve25519 Private Key and has registered the Public Keys of allowed peers.