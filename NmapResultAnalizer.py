import os
import re
from datetime import datetime

# --- Configuración ---
# El script buscará archivos de escaneo (.txt) en el mismo directorio donde se ejecuta.
SCAN_RESULTS_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_REPORT_FILE = "acceso_remoto_reporte.txt"

# --- Patrones y Palabras Clave para Detección ---

# Puertos comúnmente utilizados para acceso remoto o administración
REMOTE_ACCESS_PORTS = {
    "21": "FTP (posible acceso a archivos sensibles)",
    "22": "SSH (Secure Shell - Acceso remoto con alta criticidad si es vulnerable o mal configurado)",
    "23": "Telnet (Acceso remoto - Inseguro, transmite en texto plano)",
    "80": "HTTP (posible interfaz web de administración o con vulnerabilidades RCE)",
    "135": "RPC (Windows - Remote Procedure Call)",
    "139": "NetBIOS (Windows/SMB - Compartición de archivos)",
    "443": "HTTPS (posible interfaz web de administración o con vulnerabilidades RCE)",
    "445": "SMB (Windows - Server Message Block - Compartición de archivos)",
    "3306": "MySQL (acceso a base de datos)",
    "3389": "RDP (Windows Remote Desktop - Acceso gráfico remoto)",
    "5432": "PostgreSQL (acceso a base de datos)",
    "5900": "VNC (Virtual Network Computing - Acceso gráfico remoto)",
    "5901": "VNC (Virtual Network Computing - Acceso gráfico remoto)",
    "5985": "WinRM HTTP (Windows Remote Management)",
    "5986": "WinRM HTTPS (Windows Remote Management)",
    "8080": "HTTP Proxy/Admin Panel/Web Applications (comúnmente usado para interfaces administrativas)",
    "8443": "HTTPS Proxy/Admin Panel/Web Applications",
    "2000": "Cisco SCCP/varios (puede ser un vector si no se controla)",
    "5060": "SIP/varios (VoIP, posible vector de ataque)",
    "5555": "HP Data Protector (servicio de backup, potencial acceso a datos)",
    "8000": "HTTP Alternative (similar a 8080)",
    "9000": "HTTP Alternative (similar a 8080)",
    "10000": "Webmin/varios (potencial interfaz de administración)",
    # Añadir más puertos relevantes según el contexto
}

# Palabras clave en servicios/versiones/vulnerabilidades que indican acceso remoto/control
REMOTE_ACCESS_KEYWORDS = [
    "ssh", "rdp", "vnc", "telnet", "microsoft terminal service", "samba", "rpc", "netbios", "winrm",
    "remote code execution", "rce", "exploit", "backdoor", "webshell", "command execution", "login",
    "admin panel", "management interface", "control panel", "web gui", "phpmyadmin", "jenkins", "gitlab",
    "jira", "confluence", "cpanel", "plesk", "webmin", "directadmin", "weblogic", "tomcat", "jboss", "apache struts",
    "exchange", "powershell remoting", "ps-remoting", "ansible", "puppet", "chef", "saltstack", "nagios", "zabbix",
    "prtg", "routeros", "mikrotik", "ubiquiti", "fortigate", "pfsense", "vpn", "ike", "l2tp", "pptp", "open ssl"
]

# Palabras clave para túneles inversos/Dark Web (heurístico)
TUNNEL_DARKWEB_KEYWORDS = [
    "ngrok", "localhost.run", "ssh -r", "serveo", "cloudflared", "frpc", "frps", "chisel",
    "bore", "zrok", "localxpose", "sish", "tunnelr", "pagekite", "playit.gg", "localtunnel",
    "tailscale", "sshuttle", "openziti", "ziti", "pinggy", ".onion", "tor", "proxy", "socks5",
    "shadowsocks", "v2ray", "trojan", # Herramientas de túnel/evasión
    "vpn", "wireguard", "openvpn", # Algunos VPNs pueden usarse para túneles/conexiones sospechosas
    "meterpreter", "cobalt strike", "beacon", "reverse shell", "bind shell", # Post-explotación (si aparecen en logs de escaneo o versiones)
]

# Patrones para detectar versiones obsoletas (heurístico)
# Estos patrones son sensibles a la forma en que Nmap reporta las versiones.
# Se busca una concordancia de palabras clave o un patrón de versión que indique antigüedad.
OBSOLETE_VERSION_PATTERNS = [
    r"windows\s+(xp|2000|2003|nt|server\s+2003|server\s+2008(?!\s+r2))", # Old Windows versions (2008 without R2 can be old)
    r"apache\s+httpd\s+(?:1\.\d+|2\.0|2\.2)", # Older Apache versions (current major is 2.4.x)
    r"samba\s+(?:2\.\d+|3\.[0-5])", # Older Samba versions (current is 4.x)
    r"hp\s+data\s+protector\s+a\.0[0-7]\.\d+", # HP Data Protector A.07.00 (from 2016) and older
    r"openssh\s+(?:[1-6]\.\d+|7\.[0-5])", # OpenSSH versions before 7.6 (may have known issues depending on patch level)
    r"nginx\s+(?:1\.[0-9]|1\.[0-11])", # Nginx versions before 1.12 or 1.13 are quite old
    r"iis\s+(?:5\.0|6\.0|7\.0|7\.5)", # Older IIS versions (current is 10.0 for Windows Server 2016+)
    r"tomcat\s+(?:[1-7]\.\d+)", # Older Tomcat versions (current is 8.5+, 9, 10)
    r"mysql\s+(?:[1-4]\.\d+|5\.[0-5])", # Older MySQL versions (current is 5.7+, 8.0+)
    r"php\s+(?:[1-6]\.\d+|7\.[0-3])", # Older PHP versions (current is 7.4+, 8.x)
    r"bind\s+9\.[0-8]", # Older BIND 9 versions
    r"openssl\s+1\.0\.[012]", # Very old OpenSSL versions
    r"microsoft\s+sql\s+server\s+(?:2000|2005|2008(?!\s+r2)|2012)", # Older SQL Server versions
    r"cisco\s+ios\s+software\s+(?:12\.\d+|15\.[0-2])", # Older Cisco IOS versions
]


# --- Funciones de Detección ---

def analyze_nmap_file(filepath):
    """
    Analiza un archivo de escaneo Nmap y extrae información relevante.
    Retorna un diccionario con detalles del host y hallazgos, o None si el host no está activo.
    """
    findings = {
        "ip": "N/A",
        "os_guess": "N/A",
        "open_ports": [],
        "vulnerabilities": [],
        "remote_access_risks": [],
        "tunnel_darkweb_indicators": [],
        "obsolete_versions": []
    }

    try:
        with open(filepath, 'r', errors='ignore') as f: # Added errors='ignore' for potential encoding issues
            content = f.read()
    except FileNotFoundError:
        print(f"Advertencia: Archivo no encontrado {filepath}")
        return None

    # Verificar si el host estaba activo
    if "0 hosts up" in content:
        # Nmap reporta que el host no estaba activo, no hay puertos ni servicios que analizar
        return None 

    # Extraer IP
    ip_match = re.search(r"Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", content)
    if ip_match:
        findings["ip"] = ip_match.group(1)
    else:
        # Si no se encuentra la IP, probablemente no es un archivo de escaneo Nmap válido o está incompleto
        return None 

    # Extraer OS (guess)
    os_match = re.search(r"Running \(JUST GUESSING\): (.*?)(?:\n|$)", content, re.IGNORECASE)
    if os_match:
        findings["os_guess"] = os_match.group(1).strip()
    else:
        # Try to find OS from "OS CPE" if "JUST GUESSING" is not present
        cpe_os_match = re.search(r"OS CPE: cpe:/o:([^:]+):([^:]+)", content, re.IGNORECASE)
        if cpe_os_match:
            os_name = cpe_os_match.group(1).replace('_', ' ').title()
            os_version = cpe_os_match.group(2).replace('_', ' ')
            findings["os_guess"] = f"{os_name} {os_version}"
        else:
            findings["os_guess"] = "Desconocido"


    # Extraer puertos abiertos, servicios y versiones
    # Se ha ajustado la regex para ser más precisa en la captura de la línea de puertos
    port_lines = re.findall(r"^(\d+)/tcp\s+(?:open|open\|filtered)\s+([a-zA-Z0-9\-\?\._]+)\s*(.*)$", content, re.MULTILINE)
    
    for port, service, version in port_lines:
        service_stripped = service.strip()
        version_stripped = version.strip() if version else "N/A"
        port_info = {"port": port, "service": service_stripped, "version": version_stripped}
        findings["open_ports"].append(port_info)

        # Detección de riesgos de acceso remoto por puerto
        if port in REMOTE_ACCESS_PORTS:
            findings["remote_access_risks"].append(f"Puerto {port} ({REMOTE_ACCESS_PORTS[port]}) abierto. Posible punto de acceso o administración.")
        
        # Detección de riesgos de acceso remoto por palabra clave en servicio/versión
        full_service_info = f"{service_stripped} {version_stripped}".lower()
        for keyword in REMOTE_ACCESS_KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', full_service_info):
                risk_msg = f"Servicio/versión '{service_stripped} {version_stripped}' en puerto {port} contiene palabra clave de acceso remoto: '{keyword}'."
                if risk_msg not in findings["remote_access_risks"]: # Evitar duplicados
                    findings["remote_access_risks"].append(risk_msg)

        # Detección de indicadores de túnel/darkweb por palabra clave en servicio/versión
        for keyword in TUNNEL_DARKWEB_KEYWORDS:
            if re.search(r'\b' + re.escape(keyword) + r'\b', full_service_info):
                indicator_msg = f"Servicio/versión '{service_stripped} {version_stripped}' en puerto {port} contiene palabra clave de túnel/darkweb: '{keyword}'."
                if indicator_msg not in findings["tunnel_darkweb_indicators"]: # Evitar duplicados
                    findings["tunnel_darkweb_indicators"].append(indicator_msg)

        # Detección de versiones obsoletas (heurístico)
        for pattern_str in OBSOLETE_VERSION_PATTERNS:
            if re.search(pattern_str, full_service_info, re.IGNORECASE):
                obsolete_msg = f"Versión potencialmente obsoleta detectada en puerto {port}: '{service_stripped} {version_stripped}' (coincide con patrón '{pattern_str}')."
                if obsolete_msg not in findings["obsolete_versions"]: # Evitar duplicados
                    findings["obsolete_versions"].append(obsolete_msg)

    # Extraer vulnerabilidades de scripts NSE
    # Buscaremos líneas que empiecen con '|_' o '|   ' y que contengan CVE o palabras clave de vulnerabilidad.
    # Se excluyen mensajes de "Couldn't find" o "No reply"
    vuln_pattern = re.compile(
        r"^(?:\|\s+|_)\s+([^\n]+(?:CVE-\d{4}-\d+|VULNERABLE|EXPLOIT|CRITICAL|HIGH|MEDIUM|LOW|error: script execution failed).*)$",
        re.MULTILINE | re.IGNORECASE
    )
    vuln_lines = vuln_pattern.findall(content)
    
    for line in vuln_lines:
        vuln_text = line.strip().replace("_", "").replace("|", "").strip()
        # Filtrar líneas que son reportes de "no encontrado" o "no vulnerable"
        if not re.search(r"(couldn't find|no reply|no vulnerabilities|not vulnerable|could not be identified|no http-enum results)", vuln_text.lower()):
            if vuln_text not in findings["vulnerabilities"]: # Evitar duplicados exactos
                findings["vulnerabilities"].append(vuln_text)
            
                # Re-evaluar por keywords si la vulnerabilidad es un error o indica algo específico
                if "error: script execution failed" in vuln_text.lower():
                    error_msg = f"Error al ejecutar script de vulnerabilidad, posible fallo de detección: {vuln_text}"
                    if error_msg not in findings["remote_access_risks"]:
                        findings["remote_access_risks"].append(error_msg)
                
                # Check for remote access keywords within the vulnerability description
                for keyword in REMOTE_ACCESS_KEYWORDS:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', vuln_text.lower()):
                        risk_msg = f"Vulnerabilidad reportada contiene palabra clave de acceso remoto: '{keyword}' - Detalle: {vuln_text}"
                        if risk_msg not in findings["remote_access_risks"]: # Evitar duplicados
                            findings["remote_access_risks"].append(risk_msg)

                # Check for tunnel/darkweb keywords within the vulnerability description
                for keyword in TUNNEL_DARKWEB_KEYWORDS:
                    if re.search(r'\b' + re.escape(keyword) + r'\b', vuln_text.lower()):
                        indicator_msg = f"Vulnerabilidad reportada contiene palabra clave de túnel/darkweb: '{keyword}' - Detalle: {vuln_text}"
                        if indicator_msg not in findings["tunnel_darkweb_indicators"]: # Evitar duplicados
                            findings["tunnel_darkweb_indicators"].append(indicator_msg)

    # Chequeo adicional para túneles inversos/darkweb en el contenido general del archivo
    # Esto captura menciones no ligadas a un puerto/servicio específico, ej. en comentarios de Nmap.
    for keyword in TUNNEL_DARKWEB_KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', content.lower()):
            general_indicator_msg = f"Palabra clave de túnel/darkweb encontrada en el contenido general del escaneo: '{keyword}'."
            # Solo añadir si no fue ya detectado en servicio/versión o línea de vulnerabilidad
            if not any(keyword in existing_indicator for existing_indicator in findings["tunnel_darkweb_indicators"]):
                findings["tunnel_darkweb_indicators"].append(general_indicator_msg)

    return findings

def generate_report(all_findings):
    """
    Genera un informe consolidado en un archivo de texto.
    """
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(OUTPUT_REPORT_FILE, 'w') as out_f:
        out_f.write(f"--- Consolidated Nmap Scan Report ---\n")
        out_f.write(f"Generation Date: {current_time}\n")
        out_f.write(f"Location: Los Teques, Miranda, Venezuela\n")
        out_f.write(f"Scans Directory Analyzed: {SCAN_RESULTS_DIR}\n")
        out_f.write(f"--------------------------------------------------\n\n")

        found_any_significant_finding = False # Flag para saber si se encontró algo relevante en general

        for host_findings in all_findings:
            # Solo generar sección si hay algo relevante que reportar para este host
            if host_findings["open_ports"] or \
               host_findings["vulnerabilities"] or \
               host_findings["remote_access_risks"] or \
               host_findings["tunnel_darkweb_indicators"] or \
               host_findings["obsolete_versions"]:
                
                found_any_significant_finding = True
                out_f.write(f"### Findings for IP: {host_findings['ip']} ###\n")
                out_f.write(f"Estimated OS: {host_findings['os_guess']}\n")
                
                out_f.write(f"\n--- Open Ports Detected ---\n")
                if host_findings["open_ports"]:
                    for p in host_findings["open_ports"]:
                        out_f.write(f"  Port: {p['port']}/tcp, Service: {p['service']}, Version: {p['version']}\n")
                else:
                    out_f.write("  No open ports detected in the scan.\n")

                if host_findings["vulnerabilities"]:
                    out_f.write(f"\n--- VULNERABILITIES REPORTED BY Nmap NSE ---\n")
                    for vuln in host_findings["vulnerabilities"]:
                        out_f.write(f"  [VULNERABILITY]: {vuln}\n")
                else:
                    out_f.write(f"\n--- Vulnerabilities Reported by Nmap NSE ---\n")
                    out_f.write("  No explicit vulnerabilities reported by Nmap scripts.\n")

                if host_findings["obsolete_versions"]:
                    out_f.write(f"\n--- POTENTIALLY OBSOLETE VERSIONS DETECTED ---\n")
                    for obs_version in host_findings["obsolete_versions"]:
                        out_f.write(f"  [OBSOLETE]: {obs_version}\n")
                else:
                    out_f.write(f"\n--- Potentially Obsolete Versions Detected ---\n")
                    out_f.write("  No obviously obsolete software versions detected.\n")

                if host_findings["remote_access_risks"]:
                    out_f.write(f"\n--- POTENTIAL REMOTE ACCESS / REMOTE CONTROL RISKS ---\n")
                    for risk in host_findings["remote_access_risks"]:
                        out_f.write(f"  [RISK]: {risk}\n")
                else:
                    out_f.write(f"\n--- Potential Remote Access / Remote Control Risks ---\n")
                    out_f.write("  No obvious remote access or control risks detected based on ports/services/versions/vulnerabilities.\n")
                
                if host_findings["tunnel_darkweb_indicators"]:
                    out_f.write(f"\n--- POSSIBLE REVERSE TUNNEL / DARK WEB INDICATORS ---\n")
                    for indicator in host_findings["tunnel_darkweb_indicators"]:
                        out_f.write(f"  [INDICATOR]: {indicator}\n")
                else:
                    out_f.write(f"\n--- Possible Reverse Tunnel / Dark Web Indicators ---\n")
                    out_f.write("  No indicators of reverse tunnels or dark web connections detected.\n")
                
                out_f.write(f"--------------------------------------------------\n\n")
        
        if not found_any_significant_finding:
            out_f.write("No significant findings (remote access risks, tunnel indicators, vulnerabilities, or obsolete versions) were found in the analyzed scans.\n")
        
        out_f.write(f"--- End of Report ---")

# --- Ejecución Principal ---
if __name__ == "__main__":
    all_scan_findings = []
    
    print(f"Analyzing Nmap scan files in the current directory: {SCAN_RESULTS_DIR}")
    
    # List files and filter only .txt
    scan_files = [f for f in os.listdir(SCAN_RESULTS_DIR) if f.endswith(".txt")]
    
    if not scan_files:
        print(f"No .txt Nmap scan files found in '{SCAN_RESULTS_DIR}'. Please ensure the files are in the same folder as the script.")
        exit(0) # Exit gracefully if no files found

    for filename in scan_files:
        filepath = os.path.join(SCAN_RESULTS_DIR, filename)
        print(f"  Processing: {filename}")
        findings = analyze_nmap_file(filepath)
        if findings: # Only add if analyze_nmap_file returned a valid findings dictionary (i.e., IP was found and host was up)
            all_scan_findings.append(findings)

    if all_scan_findings:
        generate_report(all_scan_findings)
        print(f"\nAnalysis complete! The report has been saved to: {OUTPUT_REPORT_FILE}")
    else:
        print("\nNo valid scan files could be processed or no active hosts were found in the scans. Please ensure Nmap .txt files contain valid scan results (with detectable IP and active hosts).")

    # --- New addition for author information ---
    print("\n--------------------------------------------------")
    print("This script was developed by Alex Cabello, Cybersecurity Consultant.")
    print("--------------------------------------------------")