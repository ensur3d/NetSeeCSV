#!/usr/bin/env python3
"""
NetSeeCSV for Linux
Displays all active TCP/UDP connections including IPv4 and IPv6
"""

import sys
import csv
import subprocess
import threading
import re
import os
import webbrowser
import ipaddress
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QPushButton, QLabel,
    QLineEdit, QComboBox, QCheckBox, QMenu, QMessageBox, QFileDialog,
    QDialog, QStatusBar, QGridLayout, QTabWidget
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction

LIGHT_STYLE = """
QMainWindow, QDialog { background-color: #f0f0f0; }
QWidget { background-color: #f0f0f0; color: #000000; }
QTreeWidget { background-color: #ffffff; color: #000000; alternate-background-color: #f5f5f5; }
QTreeWidget::item:selected { background-color: #3478e8; color: #ffffff; }
QHeaderView::section { background-color: #e0e0e0; color: #000000; font-weight: bold; padding: 4px; border: 1px solid #cccccc; }
QPushButton { background-color: #e0e0e0; color: #000000; border: 1px solid #cccccc; padding: 4px 12px; }
QPushButton:hover { background-color: #d0d0d0; }
QLabel { color: #000000; background: transparent; }
QLineEdit, QComboBox { background-color: #ffffff; color: #000000; border: 1px solid #cccccc; padding: 2px; }
QComboBox QAbstractItemView { background-color: #ffffff; color: #000000; }
QCheckBox { color: #000000; background: transparent; spacing: 4px; }
QCheckBox::indicator { border: 2px solid #666666; width: 13px; height: 13px; border-radius: 2px; }
QCheckBox::indicator:checked { background-color: #3478e8; border-color: #3478e8; }
QMenuBar { background-color: #f0f0f0; color: #000000; }
QMenuBar::item:selected { background-color: #3478e8; color: #ffffff; }
QMenu { background-color: #f0f0f0; color: #000000; }
QMenu::item:selected { background-color: #3478e8; color: #ffffff; }
QStatusBar { background-color: #f0f0f0; color: #000000; }
QScrollBar:vertical { background: #e0e0e0; width: 12px; }
QScrollBar::handle:vertical { background: #b0b0b0; min-height: 20px; }
"""

DARK_STYLE = """
QMainWindow, QDialog { background-color: #2b2b2b; }
QWidget { background-color: #2b2b2b; color: #ffffff; }
QTreeWidget { background-color: #333333; color: #ffffff; alternate-background-color: #3a3a3a; }
QTreeWidget::item:selected { background-color: #4a4a4a; color: #ffffff; }
QHeaderView::section { background-color: #3a3a3a; color: #ffffff; font-weight: bold; padding: 4px; border: 1px solid #555555; }
QPushButton { background-color: #3a3a3a; color: #ffffff; border: 1px solid #555555; padding: 4px 12px; }
QPushButton:hover { background-color: #4a4a4a; }
QLabel { color: #ffffff; background: transparent; }
QLineEdit, QComboBox { background-color: #333333; color: #ffffff; border: 1px solid #555555; padding: 2px; }
QComboBox QAbstractItemView { background-color: #333333; color: #ffffff; }
QCheckBox { color: #ffffff; background: transparent; spacing: 4px; }
QCheckBox::indicator { border: 2px solid #aaaaaa; width: 13px; height: 13px; border-radius: 2px; }
QCheckBox::indicator:checked { background-color: #4a9eff; border-color: #4a9eff; }
QMenuBar { background-color: #2b2b2b; color: #ffffff; }
QMenuBar::item:selected { background-color: #4a4a4a; }
QMenu { background-color: #2b2b2b; color: #ffffff; }
QMenu::item:selected { background-color: #4a4a4a; }
QStatusBar { background-color: #2b2b2b; color: #ffffff; }
QScrollBar:vertical { background: #3a3a3a; width: 12px; }
QScrollBar::handle:vertical { background: #555555; min-height: 20px; }
"""


class NetworkMonitor(QMainWindow):
    update_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)
    refresh_complete_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSeeCSV")
        self.resize(1000, 600)

        self.connections = []
        self.refreshing = False
        self.auto_refresh_enabled = False
        self.auto_refresh_interval = 4000
        self.dark_mode = True

        central = QWidget()
        self.setCentralWidget(central)
        self.main_layout = QVBoxLayout(central)
        self.main_layout.setContentsMargins(5, 5, 5, 5)

        self.create_menu()
        self.create_toolbar()
        self.create_treeview()
        self.create_status_bar()

        self.auto_refresh_timer = QTimer()
        self.auto_refresh_timer.timeout.connect(self.refresh_connections)

        self.update_signal.connect(self.update_connection_tree)
        self.error_signal.connect(self.show_error)
        self.refresh_complete_signal.connect(self._refresh_complete)

        self.apply_style()
        self.refresh_connections()

    def create_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        file_menu.addAction("Import CSV", self.import_csv)
        file_menu.addAction("Export to CSV", self.export_csv)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close)

        view_menu = menubar.addMenu("View")
        self.dark_mode_action = QAction("Dark Mode", checkable=True)
        self.dark_mode_action.triggered.connect(self.toggle_dark_mode)
        view_menu.addAction(self.dark_mode_action)

        help_menu = menubar.addMenu("Help")
        help_menu.addAction("About", self.show_about)

    def create_toolbar(self):
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_connections)
        toolbar_layout.addWidget(self.refresh_btn)

        self.filter_btn = QPushButton("Filter")
        self.filter_btn.clicked.connect(self.show_filters)
        toolbar_layout.addWidget(self.filter_btn)

        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_csv)
        toolbar_layout.addWidget(self.export_btn)

        self.ip_lookup_btn = QPushButton("IP Lookup")
        self.ip_lookup_btn.clicked.connect(self.show_ip_lookup)
        toolbar_layout.addWidget(self.ip_lookup_btn)

        toolbar_layout.addStretch()

        self.auto_refresh_cb = QCheckBox("Auto-refresh")
        self.auto_refresh_cb.stateChanged.connect(self.toggle_auto_refresh)
        toolbar_layout.addWidget(self.auto_refresh_cb)

        self.main_layout.addWidget(toolbar)

    def create_treeview(self):
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)

        self.tree = QTreeWidget()
        self.live_tree = self.tree
        self._setup_tree_widget(self.tree)
        self.tab_widget.addTab(self.tree, "Live Scan")

        self.main_layout.addWidget(self.tab_widget)

    def _setup_tree_widget(self, tree):
        tree.setColumnCount(8)
        tree.setHeaderLabels([
            "Protocol", "Local Address", "Local Port", "Remote Address",
            "Remote Port", "State", "PID", "Process"
        ])
        tree.setAlternatingRowColors(True)
        tree.setRootIsDecorated(False)
        tree.setSortingEnabled(True)
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self.show_context_menu)

        widths = [80, 180, 100, 180, 100, 100, 70, 120]
        for i, w in enumerate(widths):
            tree.setColumnWidth(i, w)

        tree.header().setStretchLastSection(True)

    def _on_tab_changed(self, index):
        self.tree = self.tab_widget.widget(index)

    def close_tab(self, index):
        if index == 0:
            return
        widget = self.tab_widget.widget(index)
        self.tab_widget.removeTab(index)
        widget.deleteLater()

    def create_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if item is None:
            return

        self.tree.setCurrentItem(item)

        menu = QMenu()
        menu.addAction("Show Connection Info", self.show_connection_details)
        menu.addAction("Kill Process", self.kill_process)
        menu.addSeparator()
        menu.addAction("Copy Local Address", self.copy_local_address)
        menu.addAction("Copy Local Port", self.copy_local_port)
        menu.addAction("Copy Remote Address", self.copy_remote_address)
        menu.addAction("Copy Remote Port", self.copy_remote_port)
        menu.exec(self.tree.mapToGlobal(pos))

    def show_filters(self):
        if self.tree is not self.live_tree:
            QMessageBox.warning(self, "Warning", "Filter is only available on the Live Scan tab")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Filter Connections")
        dialog.resize(300, 280)

        layout = QGridLayout(dialog)

        layout.addWidget(QLabel("Address Filter:"), 0, 0)
        addr_entry = QLineEdit()
        layout.addWidget(addr_entry, 0, 1)

        layout.addWidget(QLabel("Protocol:"), 1, 0)
        protocol_combo = QComboBox()
        protocol_combo.addItems(["All", "TCP", "UDP", "TCP6", "UDP6"])
        layout.addWidget(protocol_combo, 1, 1)

        layout.addWidget(QLabel("State:"), 2, 0)
        state_combo = QComboBox()
        state_combo.addItems(["All", "ESTAB", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "UNCONN"])
        layout.addWidget(state_combo, 2, 1)

        layout.addWidget(QLabel("Port Filter:"), 3, 0)
        port_entry = QLineEdit()
        layout.addWidget(port_entry, 3, 1)

        def apply_filter():
            addr = addr_entry.text().strip()
            if addr:
                try:
                    ipaddress.ip_address(addr)
                except ValueError:
                    QMessageBox.warning(dialog, "Invalid IP", "Not a valid IP address")
                    return
            port = port_entry.text().strip()
            if port:
                try:
                    p = int(port)
                    if p < 1 or p > 65535:
                        QMessageBox.warning(dialog, "Invalid Port", "Port must be between 1 and 65535")
                        return
                except ValueError:
                    QMessageBox.warning(dialog, "Invalid Port", "Port must be a number")
                    return
            self.apply_filters(protocol_combo.currentText(), state_combo.currentText(),
                               addr_entry.text(), port_entry.text())
            dialog.accept()

        btn = QPushButton("Apply")
        btn.clicked.connect(apply_filter)
        layout.addWidget(btn, 4, 0, 1, 2)

        dialog.exec()

    def apply_filters(self, protocol, state, address_filter, port_filter):
        if self.tree is not self.live_tree:
            QMessageBox.warning(self, "Warning", "Filter is only available on the Live Scan tab")
            return
        filtered = []
        for conn in self.connections:
            if protocol != "All" and protocol.lower() != conn['protocol'].lower():
                continue
            if state != "All" and state != conn['state']:
                continue
            if address_filter and address_filter not in conn['local_addr'] and address_filter not in conn['remote_addr']:
                continue
            if port_filter and port_filter not in str(conn.get('port', '')) and port_filter not in str(conn.get('remote_port', '')):
                continue
            filtered.append(conn)
        self.update_connection_tree(filtered)

    def show_ip_lookup(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("IP Lookup")
        dialog.resize(400, 200)

        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Enter IP Address:"))

        ip_entry = QLineEdit()
        layout.addWidget(ip_entry)

        def open_url(url_template):
            ip = ip_entry.text().strip()
            if not ip:
                QMessageBox.warning(dialog, "Invalid IP", "Please enter an IP address")
                return
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                QMessageBox.warning(dialog, "Invalid IP", "Not a valid IP address")
                return
            webbrowser.open(url_template.format(ip=ip))

        services = [
            ("Greynoise", "https://www.greynoise.io/viz/ip/{ip}"),
            ("Shodan", "https://www.shodan.io/search?query={ip}"),
            ("AbuseIPDB", "https://www.abuseipdb.com/check/{ip}"),
            ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{ip}"),
            ("BGP_HE", "https://bgp.he.net/ip/{ip}"),
            ("Blacklist_Check", "https://www.blacklistmaster.com/check?t={ip}"),
        ]

        btn_grid = QWidget()
        grid_layout = QGridLayout(btn_grid)
        for i, (name, url) in enumerate(services):
            btn = QPushButton(name)
            btn.clicked.connect(lambda checked, u=url: open_url(u))
            grid_layout.addWidget(btn, i // 2, i % 2)
        layout.addWidget(btn_grid)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.exec()

    def _validate_commands(self, commands):
        ALLOWED_WHITELIST = {
            ('ss', '-tulnpa'),
            ('ss', '-tulnp', '-o'),
        }
        validated = []
        for cmd in commands:
            if not isinstance(cmd, (list, tuple)):
                raise ValueError(f"Invalid command format: {cmd}")
            if not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Command contains non-string arguments: {cmd}")
            dangerous_chars = [';', '&', '|', '$', '`', '>', '<', '*', '?', '{', '}', '[', ']']
            for arg in cmd:
                for char in dangerous_chars:
                    if char in arg:
                        raise ValueError(f"Potentially dangerous character '{char}' found in command: {cmd}")
            if tuple(cmd) not in ALLOWED_WHITELIST:
                raise ValueError(f"Command not in allowed whitelist: {cmd}")
            validated.append(list(cmd))
        return validated

    def refresh_connections(self):
        if self.refreshing:
            return
        self.refreshing = True
        thread = threading.Thread(target=self._refresh_connections_thread)
        thread.daemon = True
        thread.start()

    def _refresh_connections_thread(self):
        try:
            connections = []
            ALLOWED_COMMANDS = [
                ['ss', '-tulnpa'],
                ['ss', '-tulnp', '-o'],
            ]
            validated_commands = self._validate_commands(ALLOWED_COMMANDS)
            for cmd in validated_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        connections.extend(self.parse_ss_output(result.stdout))
                except Exception as e:
                    continue

            seen = set()
            unique = []
            for conn in connections:
                key = (conn['local_addr'], conn['remote_addr'], conn['protocol'])
                if key not in seen:
                    seen.add(key)
                    unique.append(conn)

            self.update_signal.emit(unique)

        except subprocess.TimeoutExpired:
            self.error_signal.emit("Command timed out")
            self.refresh_complete_signal.emit()
        except Exception as e:
            self.error_signal.emit(f"Error refreshing connections: {str(e)}")
            self.refresh_complete_signal.emit()

    def parse_ss_output(self, output):
        connections = []
        lines = output.strip().split('\n')

        header_line = None
        for i, line in enumerate(lines):
            if line.strip().startswith('Netid'):
                header_line = i
                break

        if header_line is None:
            lines_to_process = lines
        else:
            lines_to_process = lines[header_line + 1:]

        for line in lines_to_process:
            if not line.strip():
                continue
            try:
                parts = line.split(None, 6)
                if len(parts) < 6:
                    continue

                protocol = parts[0] if len(parts) > 0 else ""
                state = parts[1] if len(parts) > 1 else ""
                recv_q = parts[2] if len(parts) > 2 else ""
                send_q = parts[3] if len(parts) > 3 else ""
                local_addr_port = parts[4] if len(parts) > 4 else ""
                remote_addr_port = parts[5] if len(parts) > 5 else ""

                pid = "-"
                process = "-"

                if len(parts) > 6:
                    process_info = parts[6]
                    if process_info.startswith('users:('):
                        try:
                            pid_match = re.search(r'pid=(\d+)', process_info)
                            if pid_match:
                                pid = pid_match.group(1)
                            name_match = re.search(r'users:\(\("([^"]+)",', process_info)
                            if name_match:
                                process = name_match.group(1)
                        except Exception:
                            pass

                remote_port = self.extract_port(remote_addr_port)
                local_addr = self.extract_address(local_addr_port)
                remote_addr = self.extract_address(remote_addr_port)

                if local_addr_port and remote_addr_port:
                    connections.append({
                        'protocol': protocol,
                        'local_addr': local_addr,
                        'remote_addr': remote_addr,
                        'state': state,
                        'pid': pid,
                        'process': process,
                        'port': self.extract_port(local_addr_port),
                        'remote_port': remote_port
                    })
            except Exception:
                continue

        return connections

    def extract_port(self, address):
        try:
            if ':' in address:
                if address.startswith('[') and ']' in address:
                    return address[address.rfind(':') + 1:]
                else:
                    return address.split(':')[-1]
            return "N/A"
        except Exception:
            return "N/A"

    def extract_address(self, address):
        try:
            if ':' in address:
                if address.startswith('[') and ']' in address:
                    start = address.find('[') + 1
                    end = address.find(']:')
                    if end > 0:
                        return address[start:end]
                    return address
                else:
                    return ':'.join(address.split(':')[:-1])
            return address
        except Exception:
            return address

    def update_connection_tree(self, connections):
        self.live_tree.clear()
        for conn in connections:
            item = QTreeWidgetItem()
            item.setText(0, conn['protocol'])
            item.setText(1, conn['local_addr'])
            item.setText(2, conn['port'])
            item.setText(3, conn['remote_addr'])
            item.setText(4, conn['remote_port'])
            item.setText(5, conn['state'])
            item.setText(6, conn['pid'])
            item.setText(7, conn['process'])
            self.live_tree.addTopLevelItem(item)

        count = len(connections)
        self.status_label.setText(f"Showing {count} connections")
        self.connections = connections
        self.refresh_complete_signal.emit()

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

    def _refresh_complete(self):
        self.refreshing = False
        if self.auto_refresh_enabled:
            self.start_auto_refresh()

    def show_connection_details(self):
        selected = self.tree.selectedItems()
        if not selected:
            return
        item = selected[0]
        vals = [item.text(i) for i in range(8)]
        details = (
            f"Protocol: {vals[0]}\n"
            f"Local Address: {vals[1]}\n"
            f"Local Port: {vals[2]}\n"
            f"Remote Address: {vals[3]}\n"
            f"Remote Port: {vals[4]}\n"
            f"State: {vals[5]}\n"
            f"PID: {vals[6]}\n"
            f"Process: {vals[7]}"
        )
        QMessageBox.information(self, "Connection Details", details)

    def kill_process(self):
        if self.tree is not self.live_tree:
            QMessageBox.warning(self, "Warning", "Can only kill processes from the Live Scan tab")
            return
        selected = self.tree.selectedItems()
        if not selected:
            return
        pid = selected[0].text(6)
        if pid == "-" or pid == "N/A":
            QMessageBox.warning(self, "Warning", "No PID available for this connection")
            return
        try:
            reply = QMessageBox.question(self, "Confirm", f"Kill process with PID {pid}?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                os.kill(int(pid), 9)
                QMessageBox.information(self, "Success", f"Process {pid} killed successfully")
                self.refresh_connections()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to kill process: {str(e)}")

    def copy_local_address(self):
        selected = self.tree.selectedItems()
        if not selected:
            return
        address = selected[0].text(1)
        QApplication.clipboard().setText(address)

    def copy_remote_address(self):
        selected = self.tree.selectedItems()
        if not selected:
            return
        address = selected[0].text(3)
        QApplication.clipboard().setText(address)

    def copy_local_port(self):
        selected = self.tree.selectedItems()
        if not selected:
            return
        port = selected[0].text(2)
        QApplication.clipboard().setText(port)

    def copy_remote_port(self):
        selected = self.tree.selectedItems()
        if not selected:
            return
        port = selected[0].text(4)
        QApplication.clipboard().setText(port)

    def import_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import CSV", "", "CSV files (*.csv)"
        )
        if not file_path:
            return

        try:
            rows = []
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header is None:
                    QMessageBox.warning(self, "Warning", "CSV file is empty")
                    return
                for row in reader:
                    if len(row) < 8:
                        continue
                    rows.append(row)

            if not rows:
                QMessageBox.warning(self, "Warning", "No valid data rows found in CSV")
                return

            tree = QTreeWidget()
            self._setup_tree_widget(tree)
            tree.setSortingEnabled(False)

            for row in rows:
                item = QTreeWidgetItem()
                item.setText(0, row[0].strip())  # Protocol
                item.setText(1, row[1].strip())  # Local Address
                item.setText(2, row[6].strip())  # Local Port
                item.setText(3, row[2].strip())  # Remote Address
                item.setText(4, row[7].strip())  # Remote Port
                item.setText(5, row[3].strip())  # State
                item.setText(6, row[4].strip())  # PID
                item.setText(7, row[5].strip())  # Process
                tree.addTopLevelItem(item)

            tree.setSortingEnabled(True)

            name = os.path.splitext(os.path.basename(file_path))[0]
            self.tab_widget.addTab(tree, name)
            self.tab_widget.setCurrentWidget(tree)

            QMessageBox.information(self, "Import Successful",
                                    f"Imported {len(rows)} connections from {os.path.basename(file_path)}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to import CSV: {str(e)}")

    def export_csv(self):
        tree = self.tree
        if not tree.topLevelItemCount():
            QMessageBox.warning(self, "Warning", "No data to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export to CSV", "", "CSV files (*.csv)"
        )
        if not file_path:
            return
        if not file_path.endswith('.csv'):
            file_path += '.csv'

        try:
            with open(file_path, 'w') as f:
                f.write("Protocol,Local Address,Remote Address,State,PID,Process,Local Port,Remote Port\n")
                for i in range(tree.topLevelItemCount()):
                    item = tree.topLevelItem(i)
                    f.write(f"{item.text(0)},{item.text(1)},{item.text(3)},"
                            f"{item.text(5)},{item.text(6)},{item.text(7)},{item.text(2)},{item.text(4)}\n")
            QMessageBox.information(self, "Success", f"Connections exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export CSV: {str(e)}")

    def toggle_auto_refresh(self):
        self.auto_refresh_enabled = not self.auto_refresh_enabled
        if self.auto_refresh_enabled:
            self.start_auto_refresh()
            QMessageBox.information(self, "Auto-refresh", "Auto-refresh enabled")
        else:
            self.stop_auto_refresh()
            QMessageBox.information(self, "Auto-refresh", "Auto-refresh disabled")

    def start_auto_refresh(self):
        self.stop_auto_refresh()
        self.auto_refresh_timer.start(self.auto_refresh_interval)

    def stop_auto_refresh(self):
        self.auto_refresh_timer.stop()

    def show_about(self):
        QMessageBox.about(self, "About",
            "NetSeeCSV\n"
            "Displays all active TCP/UDP connections on Linux\n"
            "Supports IPv4 and IPv6 addresses\n\n"
            "Features:\n"
            "- Shows all active connections (listening, established, etc.)\n"
            "- Filter by TCP/UDP, Addresses, Port and State\n"
            "- Export to CSV\n"
            "- Auto-refresh functionality\n"
            "- Dark Mode\n"
            "- Kill processes listed with connection\n"
            "- IP-Lookup feature"
        )

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.dark_mode_action.setChecked(self.dark_mode)
        self.apply_style()

    def apply_style(self):
        style = DARK_STYLE if self.dark_mode else LIGHT_STYLE
        self.setStyleSheet(style)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = NetworkMonitor()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
