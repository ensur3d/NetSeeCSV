# NetSeeCSV

A Python-based GUI application for monitoring active network connections on Linux Systems with CSV Export/Import and IPLookup Function.


<img width="1598" height="961" alt="NetSeeCSV1" src="https://github.com/user-attachments/assets/195419a6-8463-4dc7-8378-3bfeae7c4c90" />


## Requirements

- Python 3.9+
- Linux operating system with `ss` command (usually pre-installed)
- PyQt6 (install via pip)

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

## Setup Virtual Environment

Run the application in a Python virtual environment.

**Create Venv**
```bash
python3 -m venv .venv
```
**Activate Venv**
```bash
source .venv/bin/activate
```
## Install Requirements

```bash
pip install -r requirements.txt
```

## Usage

Run the application (with venv activated):
```bash
source .venv/bin/activate
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
- **Dark Mode**: Toggle between light and dark themes
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

## Right-click on any connection to access context menu options:

- **Show Process Info**: Display detailed information about the connection
- **Kill Process**: Terminate the associated process
- **Copy Local Address**: Copy the local address to clipboard
- **Copy Remote Address**: Copy the remote address to clipboard
- **Copy Local and Remote ports**: Copy ports to clipboard

## Use the View menu to toggle Dark Mode on or off for the entire application:

- **Dark Mode**: Enable/disable dark theme for the main window and all dialogs

## License

This project is open source and available under the [MIT License](LICENSE.txt).
