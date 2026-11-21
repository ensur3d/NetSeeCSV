#!/usr/bin/env bash
#
# NetSeeCSV - one-command setup and launch.
# Creates .venv (if missing), installs requirements, and runs the app.
# Usage: ./run.sh
#
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

# --- Checks -----------------------------------------------------------------

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found." >&2
    echo "Install it first, e.g.:" >&2
    echo "  Debian/Ubuntu: sudo apt update && sudo apt install python3 python3-pip python3-venv" >&2
    echo "  Fedora/RHEL:   sudo dnf install python3 python3-pip python3-virtualenv" >&2
    echo "  Arch Linux:    sudo pacman -S python python-pip python-virtualenv" >&2
    exit 1
fi

if ! command -v ss >/dev/null 2>&1; then
    echo "ERROR: 'ss' command not found (required to list connections)." >&2
    echo "Install the iproute2 package, e.g.:" >&2
    echo "  Debian/Ubuntu: sudo apt install iproute2" >&2
    echo "  Fedora/RHEL:   sudo dnf install iproute" >&2
    echo "  Arch Linux:    sudo pacman -S iproute2" >&2
    exit 1
fi

# --- Virtual environment ------------------------------------------------------

if [ ! -x .venv/bin/python ]; then
    echo "Creating virtual environment (.venv)..."
    if ! python3 -m venv .venv; then
        echo "ERROR: failed to create virtual environment." >&2
        echo "On Debian/Ubuntu you may need: sudo apt install python3-venv" >&2
        exit 1
    fi
fi

echo "Installing requirements..."
.venv/bin/pip install --quiet -r requirements.txt

# --- Launch --------------------------------------------------------------------

exec .venv/bin/python NetSeeCSV.py
