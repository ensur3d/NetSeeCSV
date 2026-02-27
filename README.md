[README.md](https://github.com/user-attachments/files/25590800/README.md)
# NetSeeCSV

A Python-based GUI application for monitoring active network connections on Linux Systems with CSV Export.

## Requirements

- Python 3.12
- Linux operating system with `ss` command (usually pre-installed)
- Linux operating system with `ps` command (usually pre-installed)
- Tkinter system package

**Note:** tkinter must be installed as a system package - it cannot be installed via pip. The virtual environment uses the system's tkinter library when installed this way.

### Run Main: System tkinter

If you prefer not to use a virtual environment:

**Ubuntu/Debian/Mint:**
```bash
sudo apt update
sudo apt install python3-tk
```

**Fedora/RHEL:**
```bash
sudo dnf install python3-tkinter
```

**Arch Linux:**
```bash
sudo pacman -S python-tk
```
## Usage

Run the application (without venv):
```bash
python3 NetSeeCSV.py
```

### Setup Virtual Environment

If you prefer to run the application in a Python virtual environment.

```bash
# Install tkinter system dependency (required for GUI)
# Ubuntu/Debian/Mint:
sudo apt update && sudo apt install python3-tk

# Fedora/RHEL:
sudo dnf install python3-tkinter

# Arch Linux:
sudo pacman -S python-tk

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Verify tkinter works in venv
python -c "import tkinter; print('tkinter OK')"
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
- **Export Function**: Export connection data to CSV format
- **Auto-Refresh**: Automatically periodic updates of connection data
- **Dark Mode**: Toggle between light and dark themes
- **Context Menu**: Right-click actions for connection details and termination

## Security Features

- **Command Whitelisting**: Only pre-defined `ss` commands are allowed to execute
- **Input Validation**: All commands are validated against a strict whitelist
- **Character Sanitization**: Dangerous shell characters are blocked

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
- **Auto-refresh**: Enable/disable automatic updates

## Right-click on any connection to access context menu options:

- **Show Process Info**: Display detailed information about the connection
- **Kill Process**: Terminate the associated process
- **Copy Local Address**: Copy the local address to clipboard
- **Copy Remote Address**: Copy the remote address to clipboard

## Use the View menu to toggle Dark Mode for the entire application:

- **Dark Mode**: Enable/disable dark theme for the main window and all dialogs

## Log File

Logs are written to `network_monitor.log` in the same directory as the script.

## License

This project is open source and available under the MIT License.
