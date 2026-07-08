

# PyOdito

A command-line automated security reconnaissance and auditing tool designed to quickly inspect the attack surface of any network target (URL, FQDN, or IP address).

## 🚀 Features

- **Bulk / Multi-Target Auditing:** Input multiple targets separated by commas (e.g., github.com, 1.1.1.1, https://google.com) to audit an entire queue sequentially.

- **Smart URL & FQDN Parsing:** Automatic syntactic extraction to isolate the hostname from redundant web paths or parameters.

- **Asynchronous TCP Port Scanner:** High-performance multi-threaded network scanning to bypass blocking connection timeouts.

- **TLS Certificate Validator:** Inspects the issuing certificate authority (CA) and mathematically calculates the remaining days before expiration.

- **HTTP Security Headers Analyzer:** Automatic OWASP-aligned evaluation based on a strict 10-point compliance grading scale.

- **Automatic Protocol Failback:** Prioritizes secure HTTPS connections first, then falls back to standard HTTP if no SSL layer is found.

- **Consolidated Reporting:** Instant generation of two clean, emoji-free, professional report deliverables (`.md` and `.html`).

## 🛠️ Prerequisites & Compatibility

Before deploying the tool, ensure your local environment meets the following criteria:

- **Operating System Compatibility:**
  
  - ✔️ Windows (Fully handles asynchrony and system-specific socket error codes such as `WSAEWOULDBLOCK`)
  
  - ✔️ Linux / Unix
  
  - ✔️ macOS

- **Environment Requirement:**
  
  - Python 3.7 or higher is strictly required.

## ⚙️ Getting Started

Follow these steps to set up and execute the auditor on your local machine.

### 1. Clone the repository

Bash

```
git clone https://github.com/Aerolyse/PyOditor.git
cd your-repo
```

### 2. Install external dependency

The application relies on a single third-party module to manage application-layer web requests:

Bash

```
pip install requests
```

### 3. Run the application

Execute the main script from your terminal:

Bash

```
python PyOditor.py
```

## 💡 How to Use

The auditing workflow runs interactively and sequentially:

1. **Target Input:** Provide the target network identifier to PyOditor (e.g., `https://scanme.nmap.org/index.html` or `192.168.1.1`).

2. **Port Range Configuration:** Define the scanning boundaries by entering the initial and final port numbers.

3. **Automated Auditing:** The script concurrently executes low-level network routines and application-layer web checks.

4. **Report Verification:** Access your newly generated deliverables directly inside the root folder of the script.

## 📂 Architecture

The source code is modularly structured around Python's native utilities and the `requests` library:

### `socket`

Manages low-level network infrastructure. Used for reverse DNS resolution and dispatching asynchronous TCP SYN packets to map port accessibility.

### `threading`

Instantiates a mutual exclusion mechanism (`Lock`). Prevents multiple parallel threads from corrupting or overlapping console text outputs during concurrent network returns.

### `requests`

Queries remote web endpoints using resource-efficient `HEAD` requests to inspect application-layer metadata without downloading the full page body.

### `datetime`

Ensures strict timestamp traceability across audit deliverables and dynamically calculates time deltas for active TLS security tokens.

### `ssl`

Simulates a secure handshaking wrapper to capture, decode, and extract structural metadata from binary public key certificate chains.

### `urllib.parse`

Filters and sanitizes complex user string inputs to shield low-level socket and SSL factories from invalid URI formatting characters.

### `concurrent.futures`

Orchestrates asynchronous network load-balancing through a managed, reusable pool of 100 concurrent worker threads.

## 📊 Evaluation Matrix

The final HTTP compliance score is calculated using an index based on core OWASP security requirements:

| **HTTP Header**             | **Weight**  | **Technical Description**                                                  |
| --------------------------- | ----------- | -------------------------------------------------------------------------- |
| `Strict-Transport-Security` | **2.5 pts** | Enforces exclusive and encrypted HTTPS browser routing (HSTS).             |
| `Content-Security-Policy`   | **2.5 pts** | Strictly mitigates the risk of Cross-Site Scripting (XSS) injections.      |
| `X-Frame-Options`           | **2.0 pts** | Prohibits clickjacking attacks by preventing external frame nesting.       |
| `X-Content-Type-Options`    | **1.5 pts** | Forces the browser to strictly follow the declared server MIME type.       |
| `Referrer-Policy`           | **1.5 pts** | Restricts original origin metadata leakage during cross-domain navigation. |

## 📄 License

This project is distributed as open-source software. You are free to modify, distribute, or adapt PyOditor for your internal security testing needs.
