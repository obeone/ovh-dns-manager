# OVH DNS Manager CLI

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![PyInstaller](https://img.shields.io/badge/PyInstaller-Binary-orange)

A CLI tool for managing DNS entries on domains hosted at OVH, built with [Rich](https://github.com/Textualize/rich) for a beautiful interactive terminal experience.

```mermaid
flowchart TB
    User([User]) --> CLI[ovh-dns-manager CLI]
    CLI --> Creds[Credential Manager]
    Creds --> DotEnv[.env file]
    CLI --> OVH[OVH API]
    OVH --> Create[Create records]
    OVH --> List[List records]
    OVH --> Delete[Delete records]
    OVH --> Refresh[Refresh zone]
```

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🖥️ Interactive interface | User-friendly prompts and menus, no complex CLI arguments needed |
| 🔐 Secure credentials | OVH API keys stored in `.env` with restricted file permissions |
| 📦 Bulk creation | Create multiple subdomains at once for any record type |
| 🌐 Multi-type DNS | Support for A, AAAA, CNAME, TXT, MX and SRV records |
| 🔄 Auto-refresh | Automatic DNS zone refresh after changes |
| ♻️ Retry logic | Exponential backoff on transient network errors |

## 📋 Prerequisites

* Python 3.10 or higher
* An active OVH account with access to the domain you wish to manage

## 🛠️ Installation

### Via pipx (recommended)

```bash
pipx install git+https://github.com/obeone/ovh-dns-manager.git
```

### Via uv tool

```bash
uv tool install git+https://github.com/obeone/ovh-dns-manager.git
```

### From source

```bash
git clone https://github.com/obeone/ovh-dns-manager.git
cd ovh-dns-manager
uv venv && source .venv/bin/activate
uv pip install -e .
```

---

## 🔑 Configuration (OVH API Token)

To use this tool, you need to generate API credentials.

1. Visit the [OVH Create Token page](https://api.ovh.com/createToken/)
2. Log in with your OVH ID
3. Fill in the form:
   * **Script name:** `OVH DNS Manager` (or your preference)
   * **Description:** CLI for DNS management
   * **Validity:** `Unlimited` (recommended for local scripts)
   * **Rights:**

   | Method | Path |
   |--------|------|
   | `GET` | `/domain/zone/*` |
   | `POST` | `/domain/zone/*` |
   | `PUT` | `/domain/zone/*` |
   | `DELETE` | `/domain/zone/*` |

4. Click **Create keys**
5. Keep the **Application Key**, **Application Secret**, and **Consumer Key** handy

---

## 💻 Usage

### DNS Manager

```bash
ovh-dns-manager           # Interactive DNS management
ovh-dns-manager -v        # Verbose mode (DEBUG logging)
python -m ovh_dns_manager # Alternative invocation
```

| Menu option | Description |
|-------------|-------------|
| 1. Create | Create DNS records for one or more subdomains |
| 2. List | Display all records in a formatted table |
| 3. Delete | Remove records filtered by subdomain and type |
| 4. Exit | Close the application |

### Credentials Manager

```bash
ovh-dns-credentials       # Manage saved API credentials
```

| Menu option | Description |
|-------------|-------------|
| 1. Save | Prompt for API keys and save to `.env` |
| 2. View | Show current configuration (secrets masked) |
| 3. Delete | Remove the `.env` file |
| 4. Exit | Close the credentials manager |

---

## 🔒 Security Note

* **Local Storage:** Credentials are stored in a `.env` file in the project root
* **Permissions:** On Unix-like systems, file permissions are set to `600` (owner read/write only)
* **Version Control:** **NEVER** commit your `.env` file to Git

---

## 📂 Project Structure

```
ovh_dns_manager/
├── __init__.py       # Package version
├── __main__.py       # python -m support
├── cli.py            # CLI entry point, argument parsing, main loop
├── client.py         # OVH API client creation with retry logic
├── constants.py      # Shared constants and regexes
├── credentials.py    # Credential storage, loading and interactive prompts
├── dns.py            # DNS record CRUD operations
└── validation.py     # Input validation (domains, IPs, record targets)
```

---

## 👤 Author

Yannis Duvignau (yduvignau@snapp.fr)
