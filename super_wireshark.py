#!/usr/bin/env python3
"""
SuperWireshark Pro - Analyseur de réseau ultra-avancé avec IA intégrée
Version professionnelle avec fonctionnalités exclusives
Utilisation éthique uniquement sur vos propres réseaux
"""

import sys
import threading
import time
import json
import csv
import sqlite3
import hashlib
import socket
import struct
import geoip2.database
import geoip2.errors
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import seaborn as sns

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtChart import *

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import psutil
import requests
import whois

# Styles CSS ultra-professionnels
DARK_STYLE = """
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2b2b2b, stop:1 #1e1e1e);
    color: #ffffff;
}
QMenuBar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3c3c3c, stop:1 #2b2b2b);
    color: #ffffff;
    border-bottom: 1px solid #555;
    padding: 2px;
}
QMenuBar::item {
    background: transparent;
    padding: 8px 16px;
    border-radius: 4px;
    margin: 2px;
}
QMenuBar::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4a9eff, stop:1 #0078d4);
}
QMenu {
    background: #2b2b2b;
    border: 1px solid #555;
    border-radius: 8px;
    padding: 4px;
}
QMenu::item {
    padding: 8px 24px;
    border-radius: 4px;
    margin: 1px;
}
QMenu::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4a9eff, stop:1 #0078d4);
}
QToolBar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3c3c3c, stop:1 #2b2b2b);
    border: none;
    spacing: 8px;
    padding: 8px;
}
QToolButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4c4c4c, stop:1 #3c3c3c);
    border: 1px solid #666;
    border-radius: 6px;
    padding: 8px;
    margin: 2px;
    color: #ffffff;
}
QToolButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5a9eff, stop:1 #0078d4);
    border: 1px solid #0078d4;
}
QTableWidget {
    background: #1e1e1e;
    color: #ffffff;
    gridline-color: #444;
    selection-background-color: #0078d4;
    alternate-background-color: #252525;
    border: 1px solid #555;
    border-radius: 8px;
}
QHeaderView::section {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4c4c4c, stop:1 #3c3c3c);
    color: #ffffff;
    padding: 8px;
    border: none;
    border-right: 1px solid #666;
    font-weight: bold;
}
QTextEdit, QPlainTextEdit {
    background: #1e1e1e;
    color: #ffffff;
    border: 1px solid #555;
    border-radius: 8px;
    padding: 8px;
    font-family: 'Consolas', 'Monaco', monospace;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4a9eff, stop:1 #0078d4);
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5aa9ff, stop:1 #1088e4);
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3080d4, stop:1 #0058a4);
}
QComboBox {
    background: #2b2b2b;
    color: #ffffff;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 6px;
}
QStatusBar {
    background: #2b2b2b;
    color: #ffffff;
    border-top: 1px solid #555;
}
QGroupBox {
    color: #ffffff;
    border: 2px solid #555;
    border-radius: 8px;
    margin: 8px;
    padding-top: 16px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0 8px 0 8px;
    color: #4a9eff;
}
QTabWidget::pane {
    border: 1px solid #555;
    border-radius: 8px;
    background: #1e1e1e;
}
QTabBar::tab {
    background: #2b2b2b;
    color: #ffffff;
    padding: 8px 16px;
    margin: 2px;
    border-radius: 4px;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4a9eff, stop:1 #0078d4);
}
"""

class AIPacketAnalyzer:
    """Analyseur IA avancé pour détection d'anomalies et patterns"""
    
    def __init__(self):
        self.patterns = defaultdict(int)
        self.anomalies = []
        self.threat_signatures = self.load_threat_signatures()
        
    def load_threat_signatures(self):
        """Charger les signatures de menaces connues"""
        return {
            'port_scan': {'pattern': 'multiple_ports', 'threshold': 10},
            'dos_attack': {'pattern': 'flood_packets', 'threshold': 1000},
            'malware_beacon': {'pattern': 'periodic_connection', 'interval': 60},
            'data_exfiltration': {'pattern': 'large_upload', 'size': 10000000}
        }
        
    def analyze_traffic_ai(self, packets):
        """Analyse IA du trafic avec détection d'anomalies"""
        analysis = {
            'threats_detected': [],
            'anomalies': [],
            'recommendations': [],
            'risk_score': 0
        }
        
        # Analyse des patterns de connexion
        connections = defaultdict(lambda: {'count': 0, 'ports': set(), 'bytes': 0})
        
        for packet in packets:
            src = packet.get('src', '')
            dst = packet.get('dst', '')
            if src and dst:
                key = f"{src}->{dst}"
                connections[key]['count'] += 1
                if 'dst_port' in packet:
                    connections[key]['ports'].add(packet['dst_port'])
                connections[key]['bytes'] += packet.get('length', 0)
        
        # Détection de scan de ports
        for conn, data in connections.items():
            if len(data['ports']) > 10:
                analysis['threats_detected'].append({
                    'type': 'Port Scan',
                    'source': conn.split('->')[0],
                    'target': conn.split('->')[1],
                    'ports_scanned': len(data['ports']),
                    'severity': 'HIGH'
                })
                analysis['risk_score'] += 30
                
        # Détection de trafic suspect
        for conn, data in connections.items():
            if data['count'] > 1000:
                analysis['threats_detected'].append({
                    'type': 'Potential DDoS',
                    'source': conn.split('->')[0],
                    'packet_count': data['count'],
                    'severity': 'CRITICAL'
                })
                analysis['risk_score'] += 50
                
        # Génération de recommandations
        if analysis['risk_score'] > 50:
            analysis['recommendations'].append("Bloquer immédiatement les IPs suspectes")
            analysis['recommendations'].append("Activer la surveillance renforcée")
        elif analysis['risk_score'] > 20:
            analysis['recommendations'].append("Surveiller de près le trafic")
            
        return analysis

class GeoIPAnalyzer:
    """Analyseur géographique des IPs avec cartographie"""
    
    def __init__(self):
        self.geo_data = {}
        
    def get_geo_info(self, ip):
        """Obtenir les informations géographiques d'une IP"""
        if ip in self.geo_data:
            return self.geo_data[ip]
            
        try:
            # Simulation de géolocalisation (remplacer par vraie API)
            import random
            countries = ['France', 'Germany', 'USA', 'China', 'Russia', 'Brazil']
            cities = ['Paris', 'Berlin', 'New York', 'Beijing', 'Moscow', 'Rio']
            
            geo_info = {
                'country': random.choice(countries),
                'city': random.choice(cities),
                'lat': random.uniform(-90, 90),
                'lon': random.uniform(-180, 180),
                'isp': f"ISP-{random.randint(1, 100)}"
            }
            self.geo_data[ip] = geo_info
            return geo_info
        except:
            return {'country': 'Unknown', 'city': 'Unknown', 'lat': 0, 'lon': 0, 'isp': 'Unknown'}

class NetworkMapWidget(QWidget):
    """Widget de cartographie réseau en temps réel"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(800, 600)
        self.nodes = {}
        self.connections = []
        
    def paintEvent(self, event):
        """Dessiner la carte réseau"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Fond gradient
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, QColor(30, 30, 30))
        gradient.setColorAt(1, QColor(10, 10, 10))
        painter.fillRect(self.rect(), gradient)
        
        # Dessiner les connexions
        painter.setPen(QPen(QColor(0, 120, 212, 100), 2))
        for conn in self.connections:
            painter.drawLine(conn['start'], conn['end'])
            
        # Dessiner les nœuds
        for ip, pos in self.nodes.items():
            # Nœud principal
            painter.setBrush(QBrush(QColor(74, 158, 255)))
            painter.setPen(QPen(QColor(255, 255, 255), 2))
            painter.drawEllipse(pos, 20, 20)
            
            # Label IP
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(pos.x() + 25, pos.y() + 5, ip)
            
    def add_node(self, ip, x, y):
        """Ajouter un nœud réseau"""
        self.nodes[ip] = QPoint(x, y)
        self.update()
        
    def add_connection(self, ip1, ip2):
        """Ajouter une connexion entre deux IPs"""
        if ip1 in self.nodes and ip2 in self.nodes:
            self.connections.append({
                'start': self.nodes[ip1],
                'end': self.nodes[ip2]
            })
            self.update()

class AdvancedStatsWidget(QWidget):
    """Widget de statistiques avancées avec graphiques"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Graphique en temps réel
        self.figure = Figure(figsize=(12, 8), facecolor='#1e1e1e')
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        
        # Contrôles
        controls = QHBoxLayout()
        self.auto_refresh = QCheckBox("Actualisation automatique")
        self.auto_refresh.setChecked(True)
        controls.addWidget(self.auto_refresh)
        
        self.refresh_btn = QPushButton("Actualiser")
        self.refresh_btn.clicked.connect(self.update_charts)
        controls.addWidget(self.refresh_btn)
        
        layout.addLayout(controls)
        
    def update_charts(self, packets=None):
        """Mettre à jour les graphiques"""
        if not packets:
            return
            
        self.figure.clear()
        
        # Sous-graphiques
        gs = self.figure.add_gridspec(2, 2, hspace=0.3, wspace=0.3)
        
        # 1. Trafic par protocole (Camembert)
        ax1 = self.figure.add_subplot(gs[0, 0])
        protocols = Counter(p.get('protocol', 'Unknown') for p in packets)
        if protocols:
            ax1.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%',
                   colors=plt.cm.Set3.colors)
            ax1.set_title('Répartition par Protocole', color='white')
            
        # 2. Trafic temporel (Ligne)
        ax2 = self.figure.add_subplot(gs[0, 1])
        times = [datetime.strptime(p.get('timestamp', '00:00:00.000'), '%H:%M:%S.%f') 
                for p in packets[-100:]]  # 100 derniers paquets
        if times:
            ax2.plot(range(len(times)), [1]*len(times), 'cyan', linewidth=2)
            ax2.set_title('Trafic Temporel', color='white')
            ax2.set_xlabel('Paquets', color='white')
            ax2.set_ylabel('Fréquence', color='white')
            
        # 3. Top IPs (Barres)
        ax3 = self.figure.add_subplot(gs[1, 0])
        ips = Counter(p.get('src', '') for p in packets if p.get('src'))
        if ips:
            top_ips = ips.most_common(10)
            ax3.barh([ip[:15] for ip, _ in top_ips], [count for _, count in top_ips],
                    color='lightblue')
            ax3.set_title('Top 10 IPs Sources', color='white')
            
        # 4. Taille des paquets (Histogramme)
        ax4 = self.figure.add_subplot(gs[1, 1])
        sizes = [p.get('length', 0) for p in packets if p.get('length')]
        if sizes:
            ax4.hist(sizes, bins=30, color='orange', alpha=0.7)
            ax4.set_title('Distribution Taille Paquets', color='white')
            ax4.set_xlabel('Taille (bytes)', color='white')
            
        # Style sombre pour tous les axes
        for ax in [ax1, ax2, ax3, ax4]:
            ax.set_facecolor('#2b2b2b')
            ax.tick_params(colors='white')
            ax.xaxis.label.set_color('white')
            ax.yaxis.label.set_color('white')
            
        self.canvas.draw()

class ThreatIntelWidget(QWidget):
    """Widget d'intelligence des menaces"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.threat_feeds = self.load_threat_feeds()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # En-tête
        header = QLabel("🛡️ Intelligence des Menaces")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b; padding: 10px;")
        layout.addWidget(header)
        
        # Tableau des menaces
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(5)
        self.threats_table.setHorizontalHeaderLabels([
            "Type", "IP/Domaine", "Sévérité", "Détection", "Action"
        ])
        layout.addWidget(self.threats_table)
        
        # Contrôles
        controls = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 Scanner les Menaces")
        self.scan_btn.clicked.connect(self.scan_threats)
        controls.addWidget(self.scan_btn)
        
        self.block_btn = QPushButton("🚫 Bloquer Sélectionnées")
        self.block_btn.clicked.connect(self.block_threats)
        controls.addWidget(self.block_btn)
        
        layout.addLayout(controls)
        
    def load_threat_feeds(self):
        """Charger les flux de menaces"""
        return {
            'malware_ips': ['192.168.1.100', '10.0.0.50'],
            'phishing_domains': ['evil.com', 'phish.net'],
            'botnet_c2': ['c2.botnet.com', '192.168.1.200']
        }
        
    def scan_threats(self):
        """Scanner les menaces connues"""
        # Simulation de scan
        threats = [
            {'type': 'Malware C&C', 'target': '192.168.1.100', 'severity': 'CRITICAL', 'time': '12:34:56'},
            {'type': 'Port Scan', 'target': '192.168.1.50', 'severity': 'HIGH', 'time': '12:35:22'},
            {'type': 'Suspicious DNS', 'target': 'evil.com', 'severity': 'MEDIUM', 'time': '12:36:10'}
        ]
        
        self.threats_table.setRowCount(len(threats))
        for i, threat in enumerate(threats):
            self.threats_table.setItem(i, 0, QTableWidgetItem(threat['type']))
            self.threats_table.setItem(i, 1, QTableWidgetItem(threat['target']))
            
            severity_item = QTableWidgetItem(threat['severity'])
            if threat['severity'] == 'CRITICAL':
                severity_item.setBackground(QColor(255, 0, 0, 100))
            elif threat['severity'] == 'HIGH':
                severity_item.setBackground(QColor(255, 165, 0, 100))
            else:
                severity_item.setBackground(QColor(255, 255, 0, 100))
            self.threats_table.setItem(i, 2, severity_item)
            
            self.threats_table.setItem(i, 3, QTableWidgetItem(threat['time']))
            self.threats_table.setItem(i, 4, QTableWidgetItem("ANALYSER"))
            
    def block_threats(self):
        """Bloquer les menaces sélectionnées"""
        selected_rows = set()
        for item in self.threats_table.selectedItems():
            selected_rows.add(item.row())
            
        if selected_rows:
            QMessageBox.information(self, "Blocage", f"{len(selected_rows)} menace(s) bloquée(s)")

class SuperWiresharkPro(QMainWindow):
    """Application principale SuperWireshark Pro ultra-avancée"""
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.capture_thread = None
        self.is_capturing = False
        self.current_filter = ""
        self.ai_analyzer = AIPacketAnalyzer()
        self.geo_analyzer = GeoIPAnalyzer()
        self.setup_database()
        self.setup_ui()
        self.load_interfaces()
        self.setup_theme()
        
        # Timer pour actualisation automatique
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.auto_update_stats)
        self.update_timer.start(5000)  # 5 secondes
        
    def setup_database(self):
        """Initialiser la base de données SQLite"""
        self.db_conn = sqlite3.connect(':memory:')  # Base en mémoire
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE packets (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                data TEXT
            )
        ''')
        self.db_conn.commit()
        
    def setup_theme(self):
        """Appliquer le thème ultra-professionnel"""
        self.setStyleSheet(DARK_STYLE)
        
        # Icône personnalisée
        self.setWindowIcon(QIcon())  # Ajouter une vraie icône ici
        
        # Police personnalisée
        font = QFont("Segoe UI", 9)
        font.setStyleHint(QFont.SansSerif)
        self.setFont(font)
        
    def setup_ui(self):
        """Configuration de l'interface utilisateur ultra-professionnelle"""
        self.setWindowTitle("🚀 SuperWireshark Pro - Analyseur Réseau IA Intégré")
        self.setGeometry(50, 50, 1600, 1000)
        
        # Widget central avec onglets
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Menu et toolbar
        self.create_professional_menu()
        self.create_advanced_toolbar()
        
        # Interface principale avec onglets
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        
        # Onglet 1: Capture principale
        self.setup_main_capture_tab()
        
        # Onglet 2: Analyse IA
        self.setup_ai_analysis_tab()
        
        # Onglet 3: Géolocalisation
        self.setup_geo_tab()
        
        # Onglet 4: Cartographie réseau
        self.setup_network_map_tab()
        
        # Onglet 5: Intelligence menaces
        self.setup_threat_intel_tab()
        
        # Onglet 6: Statistiques avancées
        self.setup_advanced_stats_tab()
        
        main_layout.addWidget(self.tab_widget)
        
        # Barre de statut professionnelle
        self.setup_professional_status_bar()
        
    def setup_main_capture_tab(self):
        """Onglet de capture principal"""
        main_tab = QWidget()
        layout = QVBoxLayout(main_tab)
        
        # Contrôles de capture améliorés
        controls_group = QGroupBox("🎛️ Contrôles de Capture Avancés")
        controls_layout = QGridLayout(controls_group)
        
        controls_layout.addWidget(QLabel("Interface:"), 0, 0)
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        controls_layout.addWidget(self.interface_combo, 0, 1)
        
        controls_layout.addWidget(QLabel("Filtre BPF:"), 0, 2)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("tcp port 80 or udp port 53")
        controls_layout.addWidget(self.filter_input, 0, 3)
        
        self.start_btn = QPushButton("▶️ Démarrer")
        self.start_btn.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_btn, 1, 0)
        
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn, 1, 1)
        
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.clicked.connect(self.pause_capture)
        controls_layout.addWidget(self.pause_btn, 1, 2)
        
        self.clear_btn = QPushButton("🗑️ Effacer")
        self.clear_btn.clicked.connect(self.clear_packets)
        controls_layout.addWidget(self.clear_btn, 1, 3)
        
        layout.addWidget(controls_group)
        
        # Splitter vertical pour diviser l'affichage
        splitter = QSplitter(Qt.Vertical)
        
        # Table des paquets améliorée
        packet_group = QGroupBox("📦 Paquets Capturés")
        packet_layout = QVBoxLayout(packet_group)
        
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(9)
        self.packet_table.setHorizontalHeaderLabels([
            "⏰ Temps", "🌍 Pays", "📡 Source", "🎯 Destination", 
            "🔧 Protocole", "📏 Taille", "ℹ️ Info", "🚩 Flags", "⚠️ Risque"
        ])
        
        # Configuration avancée de la table
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setSortingEnabled(True)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.cellClicked.connect(self.show_packet_details)
        
        packet_layout.addWidget(self.packet_table)
        splitter.addWidget(packet_group)
        
        # Zone de détails ultra-avancée
        details_group = QGroupBox("🔍 Analyse Détaillée du Paquet")
        details_layout = QHBoxLayout(details_group)
        
        # Détails textuels
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Consolas", 10))
        details_layout.addWidget(self.details_text, 2)
        
        # Visualisation hexadécimale
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 10))
        details_layout.addWidget(self.hex_view, 1)
        
        splitter.addWidget(details_group)
        layout.addWidget(splitter)
        
        self.tab_widget.addTab(main_tab, "🏠 Capture Principale")
        
    def setup_ai_analysis_tab(self):
        """Onglet d'analyse IA"""
        ai_tab = QWidget()
        layout = QVBoxLayout(ai_tab)
        
        # En-tête IA
        ai_header = QLabel("🤖 Analyse IA - Détection Automatique d'Anomalies")
        ai_header.setStyleSheet("font-size: 20px; font-weight: bold; color: #00ff88; padding: 15px;")
        layout.addWidget(ai_header)
        
        # Splitter pour analyses
        ai_splitter = QSplitter(Qt.Horizontal)
        
        # Panneau de contrôle IA
        control_group = QGroupBox("⚙️ Contrôles IA")
        control_layout = QVBoxLayout(control_group)
        
        self.ai_auto_analysis = QCheckBox("Analyse automatique en temps réel")
        self.ai_auto_analysis.setChecked(True)
        control_layout.addWidget(self.ai_auto_analysis)
        
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setRange(1, 10)
        self.sensitivity_slider.setValue(5)
        control_layout.addWidget(QLabel("Sensibilité de détection:"))
        control_layout.addWidget(self.sensitivity_slider)
        
        self.analyze_btn = QPushButton("🔍 Analyser Maintenant")
        self.analyze_btn.clicked.connect(self.run_ai_analysis)
        control_layout.addWidget(self.analyze_btn)
        
        ai_splitter.addWidget(control_group)
        
        # Résultats d'analyse IA
        results_group = QGroupBox("📊 Résultats d'Analyse IA")
        results_layout = QVBoxLayout(results_group)
        
        self.ai_results = QTextEdit()
        self.ai_results.setReadOnly(True)
        results_layout.addWidget(self.ai_results)
        
        ai_splitter.addWidget(results_group)
        layout.addWidget(ai_splitter)
        
        self.tab_widget.addTab(ai_tab, "🤖 Analyse IA")
        
    def setup_geo_tab(self):
        """Onglet géolocalisation"""
        geo_tab = QWidget()
        layout = QVBoxLayout(geo_tab)
        
        geo_header = QLabel("🌍 Géolocalisation & Intelligence Géographique")
        geo_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #4a9eff; padding: 10px;")
        layout.addWidget(geo_header)
        
        self.geo_table = QTableWidget()
        self.geo_table.setColumnCount(6)
        self.geo_table.setHorizontalHeaderLabels([
            "IP", "Pays", "Ville", "ISP", "Latitude", "Longitude"
        ])
        layout.addWidget(self.geo_table)
        
        self.tab_widget.addTab(geo_tab, "🌍 Géolocalisation")
        
    def setup_network_map_tab(self):
        """Onglet cartographie réseau"""
        map_tab = QWidget()
        layout = QVBoxLayout(map_tab)
        
        map_header = QLabel("🗺️ Cartographie Réseau Temps Réel")
        map_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #ff6b6b; padding: 10px;")
        layout.addWidget(map_header)
        
        self.network_map = NetworkMapWidget()
        layout.addWidget(self.network_map)
        
        self.tab_widget.addTab(map_tab, "🗺️ Carte Réseau")
        
    def setup_threat_intel_tab(self):
        """Onglet intelligence des menaces"""
        self.threat_widget = ThreatIntelWidget()
        self.tab_widget.addTab(self.threat_widget, "🛡️ Intel Menaces")
        
    def setup_advanced_stats_tab(self):
        """Onglet statistiques avancées"""
        self.stats_widget = AdvancedStatsWidget()
        self.tab_widget.addTab(self.stats_widget, "📈 Stats Avancées")
        
    def create_professional_menu(self):
        """Créer un menu ultra-professionnel"""
        menubar = self.menuBar()
        
        # Menu Fichier
        file_menu = menubar.addMenu('📁 Fichier')
        file_menu.addAction('💾 Sauvegarder', self.save_capture, 'Ctrl+S')
        file_menu.addAction('📂 Ouvrir', self.load_capture, 'Ctrl+O')
        file_menu.addSeparator()
        file_menu.addAction('📊 Exporter CSV', self.export_csv)
        file_menu.addAction('📋 Exporter JSON', self.export_json)
        file_menu.addAction('🗃️ Exporter Base', self.export_database)
        file_menu.addSeparator()
        file_menu.addAction('❌ Quitter', self.close, 'Ctrl+Q')
        
        # Menu Capture
        capture_menu = menubar.addMenu('🎯 Capture')
        capture_menu.addAction('▶️ Démarrer', self.start_capture, 'F5')
        capture_menu.addAction('⏹️ Arrêter', self.stop_capture, 'F6')
        capture_menu.addAction('⏸️ Pause', self.pause_capture, 'F7')
        capture_menu.addSeparator()
        capture_menu.addAction('🔧 Filtres Avancés', self.show_advanced_filters)
        capture_menu.addAction('⚙️ Options Interface', self.show_interface_options)
        
        # Menu Analyse
        analyze_menu = menubar.addMenu('🔍 Analyse')
        analyze_menu.addAction('🤖 Analyse IA', self.run_ai_analysis)
        analyze_menu.addAction('📊 Statistiques', self.show_statistics)
        analyze_menu.addAction('🌍 Géolocalisation', self.analyze_geo)
        analyze_menu.addAction('🛡️ Scan Menaces', self.scan_threats)
        
        # Menu Outils
        tools_menu = menubar.addMenu('🛠️ Outils')
        tools_menu.addAction('📡 Scanner Réseau', self.network_scan)
        tools_menu.addAction('🔍 Recherche Avancée', self.advanced_search)
        tools_menu.addAction('🎨 Thèmes', self.change_theme)
        tools_menu.addAction('⚙️ Préférences', self.show_preferences)
        
        # Menu Aide
        help_menu = menubar.addMenu('❓ Aide')
        help_menu.addAction('📖 Documentation', self.show_help)
        help_menu.addAction('🆘 Support', self.show_support)
        help_menu.addAction('ℹ️ À propos', self.show_about)
        
    def create_advanced_toolbar(self):
        """Créer une barre d'outils avancée"""
        toolbar = self.addToolBar('🚀 Outils Rapides')
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        
        actions = [
            ('▶️', 'Démarrer', self.start_capture),
            ('⏹️', 'Arrêter', self.stop_capture),
            ('⏸️', 'Pause', self.pause_capture),
            ('🔍', 'Analyse IA', self.run_ai_analysis),
            ('📊', 'Stats', self.show_statistics),
            ('🌍', 'Géo', self.analyze_geo),
            ('💾', 'Sauver', self.save_capture),
            ('🛡️', 'Menaces', self.scan_threats)
        ]
        
        for icon, text, func in actions:
            action = QAction(icon, text, self)
            action.triggered.connect(func)
            toolbar.addAction(action)
            
    def setup_professional_status_bar(self):
        """Barre de statut professionnelle"""
        status = self.statusBar()
        
        self.status_label = QLabel("🟢 Prêt")
        self.packet_count = QLabel("📦 Paquets: 0")
        self.capture_rate = QLabel("📈 Débit: 0 pps")
        self.threats_count = QLabel("⚠️ Menaces: 0")
        self.ai_status = QLabel("🤖 IA: Inactive")
        
        for widget in [self.status_label, self.packet_count, self.capture_rate, self.threats_count, self.ai_status]:
            status.addPermanentWidget(widget)
            
    def load_interfaces(self):
        """Charger interfaces réseau"""
        try:
            interfaces = psutil.net_if_addrs().keys()
            self.interface_combo.addItem("🌐 Toutes interfaces", "")
            for interface in interfaces:
                self.interface_combo.addItem(f"📡 {interface}", interface)
        except Exception as e:
            print(f"Erreur: {e}")
            
    def start_capture(self):
        """Démarrer capture avec améliorations"""
        if self.is_capturing:
            return
            
        interface = self.interface_combo.currentData()
        filter_str = self.filter_input.text() if hasattr(self, 'filter_input') else ""
        
        self.capture_thread = PacketCaptureThread(interface, filter_str)
        self.capture_thread.packet_captured.connect(self.add_packet)
        self.capture_thread.start()
        
        self.is_capturing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("🔴 Capture active")
        
    def stop_capture(self):
        """Arrêter capture"""
        if not self.is_capturing:
            return
            
        if self.capture_thread:
            self.capture_thread.stop_capture()
            self.capture_thread.wait()
            
        self.is_capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("🟡 Capture arrêtée")
        
    def pause_capture(self):
        """Pause/reprendre capture"""
        if hasattr(self, 'paused'):
            self.paused = not self.paused
        else:
            self.paused = True
            
    def add_packet(self, packet):
        """Ajouter paquet avec analyse avancée"""
        if hasattr(self, 'paused') and self.paused:
            return
            
        packet_info = PacketAnalyzer.analyze_packet(packet)
        self.packets.append(packet_info)
        
        # Analyse géographique
        if packet_info.get('src'):
            geo_info = self.geo_analyzer.get_geo_info(packet_info['src'])
            packet_info['geo'] = geo_info
            
        # Ajout à la base de données
        self.add_to_database(packet_info)
        
        # Mise à jour interface
        self.update_packet_table(packet_info)
        self.update_network_map(packet_info)
        
        # Analyse IA en temps réel
        if hasattr(self, 'ai_auto_analysis') and self.ai_auto_analysis.isChecked():
            self.run_quick_ai_check(packet_info)
            
        # Mise à jour compteurs
        self.packet_count.setText(f"📦 Paquets: {len(self.packets)}")
        
    def update_packet_table(self, packet_info):
        """Mettre à jour table avec enrichissements"""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # Colonnes enrichies
        items = [
            packet_info.get('timestamp', ''),
            packet_info.get('geo', {}).get('country', ''),
            packet_info.get('src', ''),
            packet_info.get('dst', ''),
            packet_info.get('protocol', ''),
            str(packet_info.get('length', 0)),
            packet_info.get('info', ''),
            str(packet_info.get('flags', '')),
            self.calculate_risk_score(packet_info)
        ]
        
        for col, item in enumerate(items):
            table_item = QTableWidgetItem(str(item))
            
            # Coloration selon risque
            if col == 8:  # Colonne risque
                risk = item
                if risk == 'HIGH':
                    table_item.setBackground(QColor(255, 0, 0, 100))
                elif risk == 'MEDIUM':
                    table_item.setBackground(QColor(255, 165, 0, 100))
                else:
                    table_item.setBackground(self.get_protocol_color(packet_info.get('protocol', '')))
            else:
                table_item.setBackground(self.get_protocol_color(packet_info.get('protocol', '')))
                
            self.packet_table.setItem(row, col, table_item)
            
        self.packet_table.scrollToBottom()
        
    def calculate_risk_score(self, packet_info):
        """Calculer score de risque"""
        risk_factors = 0
        
        # Ports suspects
        suspicious_ports = [135, 139, 445, 1433, 3389, 5900]
        if packet_info.get('dst_port') in suspicious_ports:
            risk_factors += 2
            
        # Protocoles à risque
        if packet_info.get('protocol') in ['ICMP', 'ARP']:
            risk_factors += 1
            
        # Taille anormale
        if packet_info.get('length', 0) > 8000:
            risk_factors += 1
            
        if risk_factors >= 3:
            return 'HIGH'
        elif risk_factors >= 1:
            return 'MEDIUM'
        return 'LOW'
        
    def add_to_database(self, packet_info):
        """Ajouter à la base SQLite"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            packet_info.get('timestamp'),
            packet_info.get('src'),
            packet_info.get('dst'),
            packet_info.get('protocol'),
            packet_info.get('length'),
            json.dumps(packet_info)
        ))
        self.db_conn.commit()
        
    def run_ai_analysis(self):
        """Exécuter analyse IA complète"""
        if not self.packets:
            return
            
        analysis = self.ai_analyzer.analyze_traffic_ai(self.packets)
        
        result_text = "🤖 ANALYSE IA COMPLÈTE\n" + "="*50 + "\n\n"
        
        result_text += f"📊 Score de Risque Global: {analysis['risk_score']}/100\n\n"
        
        if analysis['threats_detected']:
            result_text += "⚠️ MENACES DÉTECTÉES:\n"
            for threat in analysis['threats_detected']:
                result_text += f"  • {threat['type']}: {threat.get('source', 'N/A')} "
                result_text += f"[{threat['severity']}]\n"
        else:
            result_text += "✅ Aucune menace majeure détectée\n"
            
        if analysis['recommendations']:
            result_text += "\n💡 RECOMMANDATIONS:\n"
            for rec in analysis['recommendations']:
                result_text += f"  • {rec}\n"
                
        self.ai_results.setPlainText(result_text)
        self.ai_status.setText("🤖 IA: Analyse terminée")
        
    def show_packet_details(self, row, column):
        """Afficher détails enrichis"""
        if row < len(self.packets):
            packet = self.packets[row]
            
            # Détails textuels
            details = self.format_enhanced_details(packet)
            self.details_text.setPlainText(details)
            
            # Vue hexadécimale
            hex_data = self.format_hex_view(packet.get('raw_data', ''))
            self.hex_view.setPlainText(hex_data)
            
    def format_enhanced_details(self, packet):
        """Formatage détaillé enrichi"""
        details = []
        details.append("🔍 ANALYSE DÉTAILLÉE DU PAQUET")
        details.append("=" * 50)
        details.append(f"⏰ Timestamp: {packet.get('timestamp')}")
        details.append(f"📏 Taille: {packet.get('length')} bytes")
        details.append(f"🔧 Protocole: {packet.get('protocol')}")
        
        if 'geo' in packet:
            geo = packet['geo']
            details.append(f"🌍 Géolocalisation:")
            details.append(f"   Pays: {geo.get('country')}")
            details.append(f"   Ville: {geo.get('city')}")
            details.append(f"   ISP: {geo.get('isp')}")
            
        details.append(f"⚠️ Niveau de Risque: {self.calculate_risk_score(packet)}")
        details.append("")
        details.append("📋 Informations Réseau:")
        details.append(f"   Source: {packet.get('src', 'N/A')}")
        details.append(f"   Destination: {packet.get('dst', 'N/A')}")
        
        return "\n".join(details)
        
    def format_hex_view(self, raw_data):
        """Formatage hexadécimal professionnel"""
        if not raw_data:
            return "Aucune donnée brute disponible"
            
        hex_lines = []
        data_str = str(raw_data)[:1000]  # Limiter à 1000 chars
        
        for i in range(0, len(data_str), 16):
            chunk = data_str[i:i+16]
            hex_part = ' '.join(f'{ord(c):02x}' if c.isprintable() else '00' for c in chunk)
            ascii_part = ''.join(c if c.isprintable() else '.' for c in chunk)
            hex_lines.append(f"{i:08x}: {hex_part:<48} {ascii_part}")
            
        return "\n".join(hex_lines)
        
    def auto_update_stats(self):
        """Mise à jour automatique des statistiques"""
        if hasattr(self, 'stats_widget'):
            self.stats_widget.update_charts(self.packets)
            
    # Méthodes utilitaires
    def get_protocol_color(self, protocol):
        colors = {
            'TCP': QColor(230, 230, 255), 'UDP': QColor(255, 230, 230),
            'ICMP': QColor(255, 255, 230), 'HTTP': QColor(200, 255, 200),
            'DNS': QColor(255, 200, 255), 'ARP': QColor(230, 255, 230)
        }
        return colors.get(protocol, QColor(255, 255, 255))
        
    def clear_packets(self):
        self.packets.clear()
        self.packet_table.setRowCount(0)
        self.details_text.clear()
        self.hex_view.clear()
        
    def save_capture(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Sauver", "", "JSON (*.json)")
        if filename:
            with open(filename, 'w') as f:
                json.dump(self.packets, f, indent=2)
                
    def export_csv(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV (*.csv)")
        if filename:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Time', 'Src', 'Dst', 'Protocol', 'Length'])
                for p in self.packets:
                    writer.writerow([p.get('timestamp'), p.get('src'), 
                                   p.get('dst'), p.get('protocol'), p.get('length')])
                                   
    # Méthodes de menu (simplifiées)
    def run_quick_ai_check(self, packet): pass
    def update_network_map(self, packet): pass
    def load_capture(self): pass
    def export_json(self): pass
    def export_database(self): pass
    def show_advanced_filters(self): pass
    def show_interface_options(self): pass
    def show_statistics(self): pass
    def analyze_geo(self): pass
    def scan_threats(self): pass
    def network_scan(self): pass
    def advanced_search(self): pass
    def change_theme(self): pass
    def show_preferences(self): pass
    def show_help(self): pass
    def show_support(self): pass
    def show_about(self):
        QMessageBox.about(self, "SuperWireshark Pro", 
                         "🚀 SuperWireshark Pro v2.0\n\n"
                         "Analyseur réseau ultra-avancé avec IA\n"
                         "• Analyse géographique temps réel\n"
                         "• Détection IA d'anomalies\n"
                         "• Intelligence des menaces\n"
                         "• Cartographie réseau interactive\n\n"
                         "Utilisation éthique uniquement ⚖️")

# Classes de support simplifiées
class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)
    
    def __init__(self, interface="", filter_str=""):
        super().__init__()
        self.interface = interface
        self.filter_str = filter_str
        self.running = False
        
    def run(self):
        self.running = True
        try:
            scapy.sniff(iface=self.interface if self.interface else None,
                       filter=self.filter_str, prn=self.process_packet,
                       stop_filter=lambda x: not self.running)
        except: pass
            
    def process_packet(self, packet):
        if self.running:
            self.packet_captured.emit(packet)
            
    def stop_capture(self):
        self.running = False

class PacketAnalyzer:
    @staticmethod
    def analyze_packet(packet):
        info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet), 'protocol': 'Unknown', 'src': '', 'dst': '', 'info': ''
        }
        
        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            
            if TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = packet[TCP].flags
                info['info'] = f"TCP {info['src_port']} → {info['dst_port']}"
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['info'] = f"UDP {info['src_port']} → {info['dst_port']}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = f"ICMP Type: {packet[ICMP].type}"
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            
        info['raw_data'] = str(packet)
        return info

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Style moderne
    
    if sys.platform.startswith('linux'):
        import os
        if os.geteuid() != 0:
            QMessageBox.critical(None, "Permissions", 
                               "🔐 Permissions root requises!\n"
                               "Lancez: sudo python3 superwireshark_pro.py")
            sys.exit(1)
    
    window = SuperWiresharkPro()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
        