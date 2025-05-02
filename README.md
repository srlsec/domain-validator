# Domain Validator (Cloudflare DNS)

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Async](https://img.shields.io/badge/async-await-brightgreen.svg)

A high-performance domain validation tool that checks DNS records via Cloudflare's DNS-over-HTTPS API, with wildcard detection and parallel processing.

## Features

- **DNS Record Validation** - Checks A, AAAA, NS, CNAME, TXT, and MX records
- **Wildcard Detection** - Identifies wildcard DNS configurations
- **Async Processing** - High-speed parallel queries (50 concurrent by default)
- **Input Cleaning** - Robust preprocessing of messy input data
- **Progress Tracking** - Real-time progress bar with tqdm
- **Comprehensive Output** - Saves only valid subdomains

## Installation

```bash
git clone https://github.com/yourusername/domain-validator.git
cd domain-validator
pip install -r requirements.txt
