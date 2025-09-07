# 📡 NetSniff

A lightweight network packet sniffer built in Rust for learning networking fundamentals and protocol analysis.

## 🚀 Current Progress - Phase 1 ✅

**Successfully implemented:**
- ✅ Network device discovery
- ✅ Listing all available interfaces (including `wlp1s0`, `lo`, etc.)
- ✅ Correctly linking with `libpcap` system library

## 🛠️ Tech Stack

- **Rust** - Systems programming
- **pcap crate** - Cross-platform packet capture interface
- **libpcap** - Low-level packet capture library

## 💻 Installation & Usage

1. **Install system dependencies:**
   ```bash
   sudo apt install libpcap-dev
