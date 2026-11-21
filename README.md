# NetSeeCSV

A Python-based GUI application for monitoring active network connections on Linux Systems with CSV Export/Import and IPLookup Function.

<img width="998" height="624" alt="Screenshot from 2026-06-27 14-28-50" src="https://github.com/user-attachments/assets/5c36f332-fcfd-434f-af2f-16745dec01f9" />

<img width="997" height="625" alt="Screenshot from 2026-06-27 14-29-43" src="https://github.com/user-attachments/assets/bf0a3923-54c9-48f5-9117-9bc2b956a705" />

## Requirements

- Python 3.9+
- Linux operating system with `ss` command (usually pre-installed)
- PyQt6 (install via pip)

## Setup
Clone Repo
```bash
git clone https://github.com/ensur3d/NetSeeCSV.git
```
Navigate to dir after cloning
```bash
cd NetSeeCSV
```

## Usage — One Command

Run the application with a single command:
```bash
./run.sh
```
That's it. `run.sh` automatically:
1. Checks that `python3` and `ss` are available (with install hints if not)
2. Creates the `.venv` virtual environment (if it doesn't exist yet)
3. Installs the requirements from `requirements.txt`
4. Launches NetSeeCSV

Safe to run again at any time — it reuses the existing `.venv` and only installs what's missing.


## Prerequisites: Install Python3

Python is usually pre-installed. Open your terminal and type `python3 --version`.
**Debian/Ubuntu**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```
**Fedora/RHEL**
```bash
sudo dnf install python3 python3-pip python3-virtualenv
```
**Arch Linux**
```bash
sudo pacman -S python python-pip python-virtualenv
```


## Alternative: Manual Setup

Prefer to manage the virtual environment yourself? Follow these steps instead of `./run.sh`:

**Create Venv**
```bash
python3 -m venv .venv
```
**Activate Venv**
```bash
source .venv/bin/activate
```
**Install Requirements**
```bash
pip install -r requirements.txt
```
**Run the application (with venv activated):**
```bash
python3 NetSeeCSV.py
```
To deactivate the venv:
```bash
deactivate
```
## Features

- **Connection Monitoring**: Displays all active TCP/UDP connections (IPv4 and IPv6)
- **Kill Process**: Terminate the associated process
- **Filtering**: Filter connections by TCP/UDP, state, address, or port
- **Import**: Import prior CSV files for review or examination.
- **Export**: Export connection data to CSV format
- **Auto-Refresh**: Automatically periodic updates of connection data
- **Themes**: Choose Light, Dark, or System (follow desktop) from the View menu
- **IP Lookup**: Lookup an IP address across multiple security services
- **Context Menu**: Right-click actions for connection details and termination

## Connection Details

- **Protocol**: TCP or UDP (IPv4/IPv6)
- **Local Address**: Local IP address and port
- **Remote Address**: Remote IP address and port
- **State**: Connection state (ESTAB, LISTEN, etc.)
- **PID**: Process ID associated with the connection
- **Process**: Name of the process using the connection
- **Local Port**: Local port number
- **Remote Port**: Remote port number

## Filtering

- **Filter by protocol**: (TCP, UDP, TCP6, UDP6)
- **Filter by connection**: state (ESTAB, LISTEN, etc.)
- **Filter by address**: (search in local or remote addresses)
- **Filter by port**: (specific port)

## Use the toolbar buttons for:

- **Refresh**: Manually refresh the connection list
- **Filter**: Apply filters to the connection list
- **Export**: Save the connection data to a CSV file
- **IP Lookup**: Look up an IP address on Greynoise, Shodan, AbuseIPDB, VirusTotal, BGP_HE, or Blacklist Check
- **Auto-refresh**: Enable/disable automatic updates

## IP Lookup

Opens a dialog to enter an IP address and look it up on popular security intelligence services:
- **Greynoise**, **Shodan**, **AbuseIPDB**, **VirusTotal**, **BGP_HE**, **Blacklist Check**

The IP Lookup window is **non-modal**: the main window stays fully interactive while it's open. You can keep working with the connection list and copy/paste between the two windows — for example, right-click a connection → *Copy Remote Address*, then click into the IP Lookup box and paste. Clicking **IP Lookup** again while the window is already open simply brings it to the front instead of opening a second one.

Right-clicking inside the address box shows a clean, icon-free menu (Undo, Redo, Cut, Copy, Paste, Select All) consistent with the rest of the app — same for the Filter dialog's input boxes.

## Right-click on any connection to access context menu options:

- **Show Process Info**: Display detailed information about the connection
- **Kill Process**: Terminate the associated process
- **Copy Local Address**: Copy the local address to clipboard
- **Copy Remote Address**: Copy the remote address to clipboard
- **Copy Local and Remote ports**: Copy ports to clipboard

## Themes (View menu)

Choose one of three themes from the View menu — exactly one is always selected, like a set of radio buttons:

- **Light**: Light theme for the main window and all dialogs
- **Dark**: Dark theme for the main window and all dialogs (default on first launch)
- **System (follow desktop)**: Automatically matches your desktop's light/dark setting and updates live if it changes

## License

This project is open source and available under the MIT License.
