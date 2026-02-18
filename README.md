# OVH DNS Manager CLI

A Python-based Command Line Interface (CLI) tool to manage your OVH DNS zones efficiently. Built with [Rich](https://github.com/Textualize/rich) for a beautiful, interactive terminal experience, this tool allows you to create, list, and delete DNS records without logging into the OVH web interface.

## 🚀 Features

* **Interactive Interface:** User-friendly prompts and menus (no complex command-line arguments needed).
* **Secure Credential Management:** safely stores your OVH API keys in a local `.env` file with restricted file permissions.
* **Bulk Creation:** Create multiple subdomains at once pointing to a specific target IP.
* **DNS Management:**
* Create `A` Records.
* List all DNS records for a domain.
* Delete records by subdomain.
* Automatic DNS Zone refresh after changes.



## 📋 Prerequisites

* Python 3.10 or higher.
* An active OVH account with access to the domain you wish to manage.

## 🛠️ Installation

1. **Clone the repository** (or download the source files):
```bash
git clone https://github.com/yannisduvignau/ovh-dns-manager.git
cd ovh-dns-manager
```


2. **Install dependencies**:
It is recommended to use a virtual environment.
```bash
# Create virtual environment (optional)
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```



## 🔑 Configuration (OVH API Token)

To use this tool, you need to generate API credentials.

1. Visit the [OVH Create Token page](https://api.ovh.com/createToken/).
2. Log in with your OVH ID.
3. Fill in the form:
* **Script name:** `OVH DNS Manager` (or your preference).
* **Description:** CLI for DNS management.
* **Validity:** `Unlimited` (recommended for local scripts).
* **Rights:** You need to add the following rights for the tool to work fully:
* `GET` `/domain/zone/*`
* `POST` `/domain/zone/*`
* `PUT` `/domain/zone/*`
* `DELETE` `/domain/zone/*`




4. Click **Create keys**.
5. Keep the **Application Key**, **Application Secret**, and **Consumer Key** handy.

## 💻 Usage

### 1. Running the Main Tool

The easiest way to start is to run `main.py`. It will automatically prompt you for credentials if they aren't saved yet.

```bash
python main.py
```

**The Main Menu:**

1. **Create DNS entry:** Prompts for subdomains (comma-separated), target IP, and TTL.
2. **List DNS entries:** Displays a formatted table of all records in the zone.
3. **Delete DNS entry:** Prompts for subdomains to remove.
4. **Exit:** Closes the application.

### 2. Managing Credentials Separately

You can manage your saved credentials directly using the helper script:

```bash
python credentials.py
```

* **Save:** Prompts for your API keys and Domain, then saves them to `.env`.
* **View:** Shows the currently loaded configuration (with secrets masked).
* **Delete:** Removes the `.env` file from your disk.

## 🔒 Security Note

* **Local Storage:** Credentials are stored in a `.env` file in the project root.
* **Permissions:** On Unix-like systems (Linux/macOS), the script automatically sets the file permissions to `600` (read/write only by the owner).
* **Version Control:** **NEVER** commit your `.env` file to Git. Ensure `.env` is listed in your `.gitignore` file.

## 📂 Project Structure

* `main.py`: The core application logic and menu system.
* `credentials.py`: Handles secure storage, retrieval, and validation of API keys.
* `requirements.txt`: List of Python libraries required (`ovh`, `rich`).