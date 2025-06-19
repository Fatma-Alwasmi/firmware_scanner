#!/usr/bin/env python3
"""
Firmware Vulnerability Scanner
This script scans an extracted firmware for common security issues.
"""

import os
import re
import sys
import subprocess
from pathlib import Path
from collections import defaultdict
import argparse
from datetime import datetime
import math
import json
import networkx as nx
from pathlib import Path
from collections import defaultdict
from patch_recommender import recommend_patches, print_patch_recommendations, export_recommendations_to_html

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"

# Severity levels
class Severity:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

# Mapping of issue types to severity levels
SEVERITY_MAPPING = {
    "ROOT_ACCOUNT": Severity.HIGH,
    "DEFAULT_ACCOUNT": Severity.MEDIUM,
    "EMPTY_PASSWORD": Severity.HIGH,
    "WEAK_PASSWORD_HASH": Severity.MEDIUM,
    "HARDCODED_CREDENTIAL": Severity.MEDIUM,
    "INSECURE_HTTP": Severity.MEDIUM,
    "AUTH_DISABLED": Severity.HIGH,
    "POSSIBLE_COMMAND_INJECTION": Severity.MEDIUM,
    "DANGEROUS_COMMAND": Severity.LOW,
    "PRIVATE_KEY_FILE": Severity.MEDIUM,
    "EMBEDDED_PRIVATE_KEY": Severity.MEDIUM
}

# Store findings for later processing
findings = defaultdict(list)
use_colors = True
show_all = False
verbose = False

def is_binary_file(file_path):
    """Check if a file is binary by reading the first few KB"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            # Count the null bytes and control characters
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            return bool(chunk.translate(None, text_chars))
    except Exception:
        return False

def contains_binary_data(line):
    """Check if a line contains likely binary data"""
    # Check if the line has more than 15% non-printable characters
    non_printable = sum(1 for c in line if not (32 <= ord(c) <= 126))
    if len(line) > 0 and non_printable / len(line) > 0.15:
        return True
    return False

def is_false_positive(line):
    """Check if a line is likely a false positive"""
    # Common strings that might be flagged as dangerous but are safe
    safe_patterns = [
        r'Cache-Control',
        r'_DYNAMIC_LINKING',
        r'GLOBAL_OFFSET_TABLE',
        r'libcfg\.so',
        r'lib.*\.so',
        r'_ftext_fdata',
        r'__bss_start',
        r'GLIBC',
        r'^\s*GCC:',
        r'^\s*gnu\.shstrtab',
        r'binary data pattern',
        r'@`%@\+'  # Common binary data pattern
    ]
    
    for pattern in safe_patterns:
        if re.search(pattern, line):
            return True
    
    # If the line has a high number of non-printable characters, it's likely binary data
    non_printable = sum(1 for c in line if not (32 <= ord(c) <= 126))
    if non_printable > 5:
        return True
        
    return False

def colorize(text, color):
    """Add color to text if color output is enabled"""
    global use_colors
    if use_colors:
        return f"{color}{text}{Colors.RESET}"
    return text

def get_severity_color(severity):
    """Return the appropriate color for a severity level"""
    if severity == Severity.HIGH:
        return Colors.RED
    elif severity == Severity.MEDIUM:
        return Colors.YELLOW
    elif severity == Severity.LOW:
        return Colors.BLUE
    return Colors.GREEN

def store_finding(file_path, issue_type, finding, line_num=None):
    """Store a finding for later processing"""
    severity = SEVERITY_MAPPING.get(issue_type, Severity.INFO)
    
    if line_num:
        location = f"{file_path}:{line_num}"
    else:
        location = file_path
        
    findings[issue_type].append({
        "file_path": file_path,
        "location": location,
        "finding": finding,
        "severity": severity,
        "line_num": line_num
    })

def print_findings():
    """Print all findings in a formatted way"""
    if not findings:
        print(colorize("\n[*] No vulnerabilities found", Colors.GREEN))
        return
        
    total_high = 0
    total_medium = 0
    total_low = 0
    total_info = 0
    
    # First print high severity findings
    print("\n" + colorize("=" * 80, Colors.BOLD))
    print(colorize(" VULNERABILITY SCAN RESULTS ", Colors.BOLD).center(80, "="))
    print(colorize("=" * 80, Colors.BOLD))
    
    # Process each severity level
    for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        # Get all issue types for this severity
        issues_for_severity = [issue for issue, findings_list in findings.items() 
                             if any(f["severity"] == severity for f in findings_list)]
        
        if not issues_for_severity:
            continue
            
        severity_color = get_severity_color(severity)
        
        print(f"\n{colorize(f'[{severity} SEVERITY FINDINGS]', severity_color)}")
        print(colorize("-" * 80, severity_color))
        
        for issue_type in sorted(issues_for_severity):
            # Get all findings for this issue type with the current severity
            current_findings = [f for f in findings[issue_type] if f["severity"] == severity]
            
            if not current_findings:
                continue
                
            # Update count
            if severity == Severity.HIGH:
                total_high += len(current_findings)
            elif severity == Severity.MEDIUM:
                total_medium += len(current_findings)
            elif severity == Severity.LOW:
                total_low += len(current_findings)
            else:
                total_info += len(current_findings)
            
            print(f"\n{colorize(f'  {issue_type} ({len(current_findings)} findings)', Colors.BOLD)}")
            
            # Limit output if there are too many findings of the same type
            if len(current_findings) > 10 and not show_all:
                sample = current_findings[:5]
                print(f"    {colorize('Showing 5 of ' + str(len(current_findings)) + ' findings (use --all to show all):', Colors.BLUE)}")
                for finding in sample:
                    print(f"    - {finding['location']}: {finding['finding']}")
                print(f"    {colorize('... ' + str(len(current_findings) - 5) + ' more findings not shown', Colors.BLUE)}")
            else:
                # For INFO severity findings, always limit to 10 examples
                if severity == Severity.INFO and len(current_findings) > 10:
                    sample = current_findings[:10]
                    print(f"    {colorize('Showing 10 of ' + str(len(current_findings)) + ' findings:', Colors.BLUE)}")
                    for finding in sample:
                        print(f"    - {finding['location']}: {finding['finding']}")
                    print(f"    {colorize('... ' + str(len(current_findings) - 10) + ' more findings not shown', Colors.BLUE)}")
                else:
                    for finding in current_findings:
                        print(f"    - {finding['location']}: {finding['finding']}")
    
    # Print summary
    print("\n" + colorize("=" * 80, Colors.BOLD))
    print(colorize(" SUMMARY ", Colors.BOLD).center(80, "="))
    print(f"HIGH severity issues:   {colorize(str(total_high), Colors.RED)}")
    print(f"MEDIUM severity issues: {colorize(str(total_medium), Colors.YELLOW)}")
    print(f"LOW severity issues:    {colorize(str(total_low), Colors.BLUE)}")
    print(f"INFO issues:            {colorize(str(total_info), Colors.GREEN)}")
    print(f"TOTAL issues:           {colorize(str(total_high + total_medium + total_low + total_info), Colors.BOLD)}")
    print(colorize("=" * 80, Colors.BOLD))

def export_findings_to_html(output_file):
    """Export findings to an HTML file with all findings displayed in a clean format"""
    try:
        # Create the directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        if not findings:
            with open(output_file, 'w') as f:
                f.write("<html><body><h1>No vulnerabilities found</h1></body></html>")
            return True
            
        html = ["""
        <html>
        <head>
            <title>Firmware Vulnerability Scan Results</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                h2 { color: #555; margin-top: 30px; }
                h3 { margin-top: 20px; }
                .high { color: #d9534f; }
                .medium { color: #f0ad4e; }
                .low { color: #5bc0de; }
                .info { color: #5cb85c; }
                .finding-section { margin-bottom: 30px; }
                .finding-table { border-collapse: collapse; width: 100%; margin-top: 10px; }
                .finding-table th, .finding-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                .finding-table th { background-color: #f2f2f2; }
                .finding-table tr:nth-child(even) { background-color: #f9f9f9; }
                .summary { margin-top: 30px; padding: 10px; background-color: #f5f5f5; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>Firmware Vulnerability Scan Results</h1>
            <p>Scan completed: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        """]
        
        total_high = 0
        total_medium = 0
        total_low = 0
        total_info = 0
        
        # Process each severity level
        for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_class = severity.lower()
            
            # Get all issue types for this severity
            issues_for_severity = [issue for issue, findings_list in findings.items() 
                                 if any(f["severity"] == severity for f in findings_list)]
            
            if not issues_for_severity:
                continue
                
            html.append(f'<h2 class="{severity_class}">{severity} SEVERITY FINDINGS</h2>')
            
            for issue_type in sorted(issues_for_severity):
                # Get all findings for this issue type with the current severity
                current_findings = [f for f in findings[issue_type] if f["severity"] == severity]
                
                if not current_findings:
                    continue
                    
                # Update count
                if severity == Severity.HIGH:
                    total_high += len(current_findings)
                elif severity == Severity.MEDIUM:
                    total_medium += len(current_findings)
                elif severity == Severity.LOW:
                    total_low += len(current_findings)
                else:
                    total_info += len(current_findings)
                
                html.append(f'<div class="finding-section">')
                html.append(f'<h3>{issue_type} ({len(current_findings)} findings)</h3>')
                
                # Display all findings in a table format for better organization
                html.append('<table class="finding-table">')
                html.append('<tr><th>Location</th><th>Description</th></tr>')
                
                for finding in current_findings:
                    html.append('<tr>')
                    html.append(f'<td>{finding["location"]}</td>')
                    html.append(f'<td>{finding["finding"]}</td>')
                    html.append('</tr>')
                
                html.append('</table>')
                html.append('</div>')
        
        # Add summary
        html.append('<div class="summary">')
        html.append('<h2>SUMMARY</h2>')
        html.append(f'<p>HIGH severity issues: <span class="high">{total_high}</span></p>')
        html.append(f'<p>MEDIUM severity issues: <span class="medium">{total_medium}</span></p>')
        html.append(f'<p>LOW severity issues: <span class="low">{total_low}</span></p>')
        html.append(f'<p>INFO issues: <span class="info">{total_info}</span></p>')
        html.append(f'<p>TOTAL issues: <strong>{total_high + total_medium + total_low + total_info}</strong></p>')
        html.append('</div>')
        
        html.append('</body></html>')
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(html))
        
        print(f"\nResults exported to {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting to HTML: {str(e)}")
        return False

def check_passwd_shadow(firmware_root):
    """Check /etc/passwd and /etc/shadow for weak credentials"""
    passwd_path = os.path.join(firmware_root, "etc", "passwd")
    shadow_path = os.path.join(firmware_root, "etc", "shadow")
    
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                for line in lines:
                    if ':x:0:' in line or ':0:0:' in line:
                        store_finding(passwd_path, "ROOT_ACCOUNT", line.strip())
                    
                    # Check for default/testing accounts
                    default_accounts = ['admin', 'guest', 'user', 'test', 'support', 'ubnt', 'root']
                    for account in default_accounts:
                        if line.startswith(f"{account}:"):
                            store_finding(passwd_path, "DEFAULT_ACCOUNT", line.strip())
        except Exception as e:
            print(f"Error reading {passwd_path}: {e}")
    
    if os.path.exists(shadow_path):
        try:
            with open(shadow_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                for line in lines:
                    # Check for empty passwords (::)
                    if re.search(r':[^:]*::', line):
                        store_finding(shadow_path, "EMPTY_PASSWORD", line.strip())
                    # Check for plaintext or weak hashes (absence of $ in hash)
                    parts = line.split(':')
                    if len(parts) > 1 and parts[1] and not '*' in parts[1] and not '$' in parts[1]:
                        store_finding(shadow_path, "WEAK_PASSWORD_HASH", line.strip())
        except Exception as e:
            print(f"Error reading {shadow_path}: {e}")

def check_config_files(firmware_root):
    """Check config files for vulnerable settings"""
    config_extensions = ['.conf', '.cfg', '.ini', '.xml', '.json']
    error_count = 0
    
    for root, _, files in os.walk(firmware_root):
        for file in files:
            if any(file.endswith(ext) for ext in config_extensions) or (file == 'config'):
                file_path = os.path.join(root, file)
                
                # Skip binary files
                if is_binary_file(file_path):
                    continue
                    
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        line_num = 0
                        
                        for line in content.splitlines():
                            line_num += 1
                            
                            # Skip lines that are likely binary data
                            if contains_binary_data(line):
                                continue
                                
                            # Check for hardcoded credentials
                            cred_patterns = [
                                r'password\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
                                r'user\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
                                r'username\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
                                r'pass\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
                                r'auth\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?',
                                r'key\s*[=:]\s*[\'"]?([^\'"\s]+)[\'"]?'
                            ]
                            
                            for pattern in cred_patterns:
                                matches = re.search(pattern, line, re.IGNORECASE)
                                if matches and not line.strip().startswith('#') and not line.strip().startswith('//'):
                                    store_finding(file_path, "HARDCODED_CREDENTIAL", line.strip(), line_num)
                            
                            # Check for HTTP instead of HTTPS
                            if 'http://' in line and not line.strip().startswith('#') and not line.strip().startswith('//'):
                                store_finding(file_path, "INSECURE_HTTP", line.strip(), line_num)
                                
                            # Check for disabled authentication
                            if re.search(r'auth\s*[=:]\s*[\'"]?(no|false|0|off)[\'"]?', line, re.IGNORECASE):
                                store_finding(file_path, "AUTH_DISABLED", line.strip(), line_num)
                except FileNotFoundError:
                    error_count += 1
                    continue
                except Exception:
                    continue
    
    if error_count > 0 and verbose:
        print(f"Note: {error_count} referenced configuration files were not found")

def check_scripts(firmware_root):
    """Check shell scripts for dangerous functions"""
    script_extensions = ['.sh', '.bash', '.cgi']
    dangerous_functions = [
        'system(', 'exec(', 'popen(', 'eval ', '`', '$(', 'curl', 'wget'
    ]
    
    for root, _, files in os.walk(firmware_root):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Check file extension
            is_script = any(file.endswith(ext) for ext in script_extensions)
            
            # If not script by extension, check if it's executable and has shebang
            if not is_script:
                try:
                    if os.access(file_path, os.X_OK):
                        with open(file_path, 'rb') as f:
                            start = f.read(20)
                            if start.startswith(b'#!/bin/sh') or start.startswith(b'#!/bin/bash'):
                                is_script = True
                except:
                    pass
            
            if is_script:
                # Skip binary files
                if is_binary_file(file_path):
                    continue
                    
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        line_num = 0
                        
                        for line in content.splitlines():
                            line_num += 1
                            
                            # Skip binary data
                            if contains_binary_data(line):
                                continue
                                
                            if line.strip().startswith('#'):
                                continue
                                
                            for func in dangerous_functions:
                                if func in line:
                                    # Only flag as command injection if there are variables being used in the command
                                    if ('$' in line or '`' in line) and not is_false_positive(line):
                                        store_finding(file_path, "POSSIBLE_COMMAND_INJECTION", line.strip(), line_num)
                                        break
                                    elif not is_false_positive(line):
                                        store_finding(file_path, "DANGEROUS_COMMAND", line.strip(), line_num)
                                        break
                except Exception as e:
                    if verbose:
                        print(f"Error reading {file_path}: {e}")

def check_private_keys(firmware_root):
    """Check for private keys and certificates"""
    private_key_patterns = [
        r'-----BEGIN .* PRIVATE KEY-----',
        r'-----BEGIN CERTIFICATE-----'
    ]
    
    for root, _, files in os.walk(firmware_root):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Check file extension
            if file.endswith('.key') or file.endswith('.pem') or file.endswith('.crt') or file.endswith('.cert'):
                store_finding(file_path, "PRIVATE_KEY_FILE", "File with private key/certificate extension found")
            
            # For larger files, just check the first few KB
            try:
                if os.path.isfile(file_path) and os.path.getsize(file_path) < 1024 * 10:  # 10 KB limit to avoid large binary files
                    # Skip binary files for content check
                    if is_binary_file(file_path):
                        continue
                        
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read(1024 * 5)  # Read first 5 KB
                            for pattern in private_key_patterns:
                                if re.search(pattern, content):
                                    store_finding(file_path, "EMBEDDED_PRIVATE_KEY", "Private key or certificate found embedded in file")
                                    break
                    except Exception:
                        pass
            except Exception:
                pass  # Skip files with issues
                
def check_dangerous_functions(firmware_root):
    """Check binaries for dangerous functions and list their memory addresses"""
    dangerous_functions = [
        "strcpy", "strcat", "sprintf", "gets", "system", "popen", 
        "exec", "fork", "daemon", "memcpy", "scanf"
    ]
    
    binary_extensions = ['.cgi', '', '.bin', '.so', '.elf', '.ko']
    
    # Walk the filesystem without following symlinks
    for root, dirs, files in os.walk(firmware_root, followlinks=False):
        # Skip the /proc directory entirely
        if '/proc' in root or root.endswith('/proc'):
            dirs[:] = []  # Clear the dirs list to skip all subdirectories
            continue
            
        # This prevents infinite loops by filtering out symlinked directories
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip symbolic links to files
            if os.path.islink(file_path):
                continue
                
            # Check if it's likely a binary file or executable script
            is_binary = False
            if any(file.endswith(ext) for ext in binary_extensions):
                is_binary = True
            elif os.access(file_path, os.X_OK):
                # Check if it's executable
                is_binary = True
            
            if is_binary and os.path.isfile(file_path):
                try:
                    # objdump to get symbol information with addresses
                    result = subprocess.run(['objdump', '-T', file_path], 
                                          capture_output=True, 
                                          text=True, 
                                          timeout=5)  # 5 second timeout
                    
                    if result.returncode == 0 and result.stdout:
                        objdump_output = result.stdout
                        
                        # Find dangerous functions in the symbol table
                        for func in dangerous_functions:
                            for line in objdump_output.splitlines():
                                # Make sure we match actual function symbols, not file paths
                                if func in line and not line.startswith(' ') and not file_path in line:
                                    parts = line.split()
                                    if parts and len(parts) > 0:
                                        try:
                                            # Validate that the address is actually a hexadecimal number
                                            address = parts[0]
                                            # Try to convert to ensure it's a valid hex
                                            int(address, 16)  # This will raise ValueError if not a valid hex
                                            store_finding(
                                                file_path, 
                                                "DANGEROUS_FUNCTION", 
                                                f"Potentially dangerous function '{func}' found at address 0x{address}"
                                            )
                                        except ValueError:
                                            # Not a valid hex address, skip this finding
                                            continue
                                        except Exception as e:
                                            print(f"Error processing objdump output for {file_path}: {e}")
                    else:
                        # Try readelf for ELF binaries
                        try:
                            result = subprocess.run(['readelf', '--symbols', file_path], 
                                                  capture_output=True, 
                                                  text=True, 
                                                  timeout=5)
                            
                            if result.returncode == 0 and result.stdout:
                                for func in dangerous_functions:
                                    if func in result.stdout:
                                        # Extract lines containing the function name
                                        for line in result.stdout.splitlines():
                                            if func in line and '@' in line:  # Look for functions with @ (like @GLIBC)
                                                store_finding(
                                                    file_path,
                                                    "DANGEROUS_FUNCTION",
                                                    f"Potentially dangerous function '{func}' referenced in binary"
                                                )
                                                break
                        except Exception:
                            pass
                
                except subprocess.TimeoutExpired:
                    print(f"Skipping file {file_path} - processing timed out")
                    continue
                except Exception as e:
                    print(f"Error analyzing {file_path}: {str(e)}")
                    continue

def analyze_firmware_components(firmware_root, findings):
    """
    Analyze firmware components, their relationships, and associated vulnerabilities
    
    Args:
        firmware_root: Path to the extracted firmware root directory
        findings: Dictionary of vulnerability findings
        
    Returns:
        Dictionary with component graph data for visualization
    """
    print(f"Starting firmware component analysis with {sum(len(issues) for issues in findings.values())} total findings")
    
    # Define component categories
    component_categories = {
        "core": ["/bin/", "/sbin/", "/lib/", "/usr/bin/", "/usr/sbin/"],
        "config": ["/etc/", "/config/"],
        "web": ["/www/", "/html/", "/web/", "/var/www/"],
        "data": ["/var/", "/data/", "/usr/share/"],
        "kernel": ["/boot/", "/lib/modules/"],
        "system": ["/proc/", "/sys/", "/dev/"],
        "network": ["/etc/network/", "/etc/ppp/", "/etc/wpa_supplicant/"]
    }
    
    # Build a simple component graph
    component_graph = nx.DiGraph()
    
    # Debug: Print some findings to verify data
    print("Sample findings:")
    count = 0
    for issue_type, issues in findings.items():
        for issue in issues[:2]:  # Print first two issues of each type
            print(f"  - {issue_type}: {issue.get('file_path', 'No path')} ({issue.get('severity', 'Unknown')})")
            count += 1
            if count >= 10:
                break
        if count >= 10:
            break
    
    # Create mapping of files to vulnerabilities
    file_vulnerabilities = defaultdict(list)
    total_files = 0
    
    for issue_type, issues in findings.items():
        for issue in issues:
            file_path = issue.get("file_path", "")
            if file_path:
                # Try to make path relative
                if file_path.startswith(firmware_root):
                    rel_path = os.path.relpath(file_path, firmware_root)
                else:
                    rel_path = file_path
                
                file_vulnerabilities[rel_path].append({
                    "type": issue_type,
                    "description": issue.get("finding", ""),
                    "severity": issue.get("severity", "INFO"),
                    "line_num": issue.get("line_num")
                })
                total_files += 1
    
    print(f"Mapped vulnerabilities to {len(file_vulnerabilities)} unique files")
    
    # Add nodes for all files with vulnerabilities
    for file_path, vulns in file_vulnerabilities.items():
        full_path = os.path.join(firmware_root, file_path)
        file_exists = os.path.exists(full_path)
        file_size = os.path.getsize(full_path) if file_exists else 0
        
        print(f"Adding node for {file_path} with {len(vulns)} vulnerabilities (exists: {file_exists})")
        
        component_graph.add_node(
            file_path, 
            type=get_file_type(full_path) if file_exists else "unknown",
            size=file_size,
            vulnerabilities=len(vulns)
        )
    
    # If the graph is empty, add some key system files
    if len(component_graph.nodes()) == 0:
        print("No vulnerable files found. Adding some key system files...")
        important_files = []
        for root, _, files in os.walk(firmware_root):
            for file in files:
                if any(keyword in file.lower() for keyword in ['passwd', 'shadow', 'config', 'init']):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, firmware_root)
                    important_files.append((rel_path, file_path))
                    if len(important_files) >= 10:
                        break
            if len(important_files) >= 10:
                break
        
        # Add these files to the graph
        for rel_path, file_path in important_files:
            print(f"Adding important file: {rel_path}")
            component_graph.add_node(
                rel_path,
                type=get_file_type(file_path),
                size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                vulnerabilities=0
            )
    
    # Create basic connections between components
    # We'll just connect files in the same directory for simplicity
    nodes = list(component_graph.nodes())
    for i, node1 in enumerate(nodes):
        dir1 = os.path.dirname(node1)
        for node2 in nodes[i+1:]:
            dir2 = os.path.dirname(node2)
            if dir1 == dir2:
                component_graph.add_edge(node1, node2, type="same directory")
                component_graph.add_edge(node2, node1, type="same directory")
    
    print(f"Created graph with {len(component_graph.nodes())} nodes and {len(component_graph.edges())} edges")
    
    # Calculate simple risk scores
    component_risk_scores = {}
    severity_values = {
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1
    }
    
    for component in component_graph.nodes():
        vulnerabilities = file_vulnerabilities.get(component, [])
        
        # Base score from severity
        base_score = sum(severity_values.get(v["severity"], 1) for v in vulnerabilities)
        
        # Simple risk score - just add 1 to ensure nothing is zero
        risk_score = base_score + 1
        
        component_risk_scores[component] = risk_score
    
    # Generate visualization data
    visualization_data = generate_visualization_data(
        component_graph, 
        file_vulnerabilities,
        component_risk_scores,
        component_categories
    )
    
    return visualization_data

def build_component_graph(firmware_root):
    """
    Build a graph of firmware components and their relationships
    
    This analyzes binary dependencies, config file references, and other 
    indicators to determine which components interact with each other.
    """
    component_graph = nx.DiGraph()
    
    # Define file patterns to identify important components
    binary_files = []
    config_files = []
    script_files = []
    library_files = []
    
    # Scan firmware directories
    for root, _, files in os.walk(firmware_root):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, firmware_root)
            
            # Skip very common system files to avoid cluttering the graph
            if any(pattern in file_path for pattern in ['/proc/', '/sys/', '/dev/']):
                continue
                
            # Add node for this file
            component_graph.add_node(rel_path, 
                                    type=get_file_type(file_path),
                                    size=os.path.getsize(file_path) if os.path.exists(file_path) else 0)
            
            # Store file by type for dependency analysis
            if os.access(file_path, os.X_OK) and not os.path.isdir(file_path):
                binary_files.append(file_path)
            elif file.endswith(('.conf', '.cfg', '.ini', '.xml', '.json')):
                config_files.append(file_path)
            elif file.endswith(('.sh', '.bash', '.cgi')):
                script_files.append(file_path)
            elif file.endswith(('.so', '.a', '.ko')):
                library_files.append(file_path)
    
    # Analyze binary dependencies (simplified)
    for binary in binary_files:
        rel_binary = os.path.relpath(binary, firmware_root)
        
        # Use ldd-like functionality to detect library dependencies
        try:
            # Check if file contains references to libraries
            with open(binary, 'rb') as f:
                content = f.read()
                
                # Look for common library patterns (simplified)
                for lib in library_files:
                    lib_name = os.path.basename(lib)
                    if lib_name.encode() in content:
                        rel_lib = os.path.relpath(lib, firmware_root)
                        component_graph.add_edge(rel_binary, rel_lib, type="uses")
        except:
            pass
    
    # Analyze config files for references to binaries and other components
    for config in config_files:
        rel_config = os.path.relpath(config, firmware_root)
        
        try:
            with open(config, 'r', errors='ignore') as f:
                content = f.read()
                
                # Look for references to binaries
                for binary in binary_files:
                    binary_name = os.path.basename(binary)
                    if binary_name in content:
                        rel_binary = os.path.relpath(binary, firmware_root)
                        component_graph.add_edge(rel_config, rel_binary, type="references")
        except:
            pass
    
    # Add relationships between scripts and binaries they call
    for script in script_files:
        rel_script = os.path.relpath(script, firmware_root)
        
        try:
            with open(script, 'r', errors='ignore') as f:
                content = f.read()
                
                for binary in binary_files:
                    binary_name = os.path.basename(binary)
                    if binary_name in content:
                        rel_binary = os.path.relpath(binary, firmware_root)
                        component_graph.add_edge(rel_script, rel_binary, type="executes")
        except:
            pass
    
    # Simplify graph by pruning isolated nodes (no connections)
    isolated_nodes = [n for n in component_graph.nodes() if component_graph.degree(n) == 0]
    for node in isolated_nodes:
        component_graph.remove_node(node)
    
    return component_graph

def get_file_type(file_path):
    """Determine the type of a file based on its extension and attributes"""
    if not os.path.exists(file_path):
        return "unknown"
        
    if os.path.isdir(file_path):
        return "directory"
        
    # Check based on extension
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in ['.so', '.a', '.ko']:
        return "library"
    elif ext in ['.conf', '.cfg', '.ini', '.xml', '.json']:
        return "config"
    elif ext in ['.sh', '.bash', '.cgi', '.pl', '.py']:
        return "script"
    elif ext in ['.key', '.pem', '.crt', '.cert']:
        return "security"
    elif ext in ['.html', '.htm', '.php', '.asp', '.jsp']:
        return "web"
    
    # Check if executable
    try:
        if os.access(file_path, os.X_OK) and not os.path.isdir(file_path):
            return "binary"
    except:
        pass
        
    return "other"

def map_vulnerabilities_to_components(findings, component_graph):
    """Map vulnerability findings to components in the graph"""
    component_vulnerabilities = defaultdict(list)
    
    for issue_type, issues in findings.items():
        for issue in issues:
            file_path = issue.get("file_path", "")
            if file_path:
                # Try to find the file in the component graph
                rel_path = os.path.basename(file_path)  # Simplified, ideally would use relative path
                
                # Find matching nodes in graph (might be multiple)
                matching_nodes = [n for n in component_graph.nodes() if rel_path in n]
                
                for node in matching_nodes:
                    component_vulnerabilities[node].append({
                        "type": issue_type,
                        "description": issue.get("finding", ""),
                        "severity": issue.get("severity", "INFO"),
                        "line_num": issue.get("line_num")
                    })
    
    return component_vulnerabilities

def calculate_component_risk_scores(component_vulnerabilities):
    """Calculate risk scores for components based on their vulnerabilities"""
    component_risk_scores = {}
    
    severity_values = {
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1
    }
    
    for component, vulnerabilities in component_vulnerabilities.items():
        # Base score from severity
        base_score = sum(severity_values.get(v["severity"], 1) for v in vulnerabilities)
        
        # Number of unique vulnerability types
        unique_types = len(set(v["type"] for v in vulnerabilities))
        
        # Calculate final score with diminishing returns for large numbers of vulnerabilities
        risk_score = base_score * (1 + 0.1 * math.log(len(vulnerabilities) + 1)) * (1 + 0.2 * unique_types)
        
        component_risk_scores[component] = risk_score
    
    return component_risk_scores

def get_component_category(component_path, component_categories):
    """Determine category of a component based on its path"""
    for category, patterns in component_categories.items():
        if any(pattern in component_path for pattern in patterns):
            return category
    return "other"

def generate_visualization_data(component_graph, component_vulnerabilities, component_risk_scores, component_categories):
    """Generate data for visualization of the component graph with vulnerability data"""
    # Handle empty graph case
    if len(component_graph.nodes()) == 0:
        print("WARNING: Empty component graph, creating dummy data for visualization")
        # Create a minimal dummy graph for visualization
        component_graph.add_node("dummy_node", type="other", size=1, vulnerabilities=0)
    
    # Calculate node sizes based on risk score or use defaults for empty data
    max_risk_score = max(component_risk_scores.values()) if component_risk_scores else 1
    
    # Create nodes list
    nodes = []
    for node in component_graph.nodes():
        node_type = component_graph.nodes[node].get('type', 'other')
        vulnerabilities_count = component_graph.nodes[node].get('vulnerabilities', 0)
        risk_score = component_risk_scores.get(node, 1)
        
        # Scale node size based on risk (with minimum size)
        size = 5 + (25 * risk_score / max_risk_score) if max_risk_score > 0 else 5
        
        # Determine category
        category = "other"
        for cat_name, patterns in component_categories.items():
            if any(pattern in str(node) for pattern in patterns):
                category = cat_name
                break
        
        # Count vulnerabilities by severity
        vulnerabilities = component_vulnerabilities.get(node, [])
        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "INFO")
            severity_counts[severity] += 1
        
        nodes.append({
            "id": node,
            "label": os.path.basename(str(node)),
            "full_path": node,
            "type": node_type,
            "category": category,
            "size": size,
            "risk_score": risk_score,
            "vulnerabilities": vulnerabilities_count,
            "severity_counts": severity_counts
        })
    
    # Create edges list
    edges = []
    for source, target, data in component_graph.edges(data=True):
        edges.append({
            "source": source,
            "target": target,
            "type": data.get("type", "connects")
        })
    
    # Group components by category for visualization clusters
    categories = {}
    for category in set(node["category"] for node in nodes):
        categories[category] = {
            "name": category,
            "count": sum(1 for node in nodes if node["category"] == category),
            "risk_score": sum(node["risk_score"] for node in nodes if node["category"] == category)
        }
    
    # Calculate overall metrics
    total_components = len(nodes)
    total_connections = len(edges)
    total_vulnerabilities = sum(node["vulnerabilities"] for node in nodes)
    total_risk_score = sum(component_risk_scores.values()) if component_risk_scores else 0
    
    # Create final visualization data structure
    visualization_data = {
        "nodes": nodes,
        "edges": edges,
        "categories": categories,
        "metrics": {
            "total_components": total_components,
            "total_connections": total_connections,
            "total_vulnerabilities": total_vulnerabilities,
            "total_risk_score": total_risk_score
        }
    }
    
    return visualization_data

def export_visualization_to_html(visualization_data, output_file):
    """Export visualization data to an interactive HTML file with connections for top components"""
    # Create the output directory if needed
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # HTML template with embedded JavaScript for vis.js network visualization
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firmware Attack Surface Visualization</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.min.js"></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                display: flex;
                height: 100vh;
            }
            
            #left-panel {
                width: 280px;
                padding: 15px;
                background-color: #f8f9fa;
                overflow-y: auto;
                border-right: 1px solid #ddd;
            }
            
            #right-panel {
                flex: 1;
                display: flex;
                flex-direction: column;
            }
            
            #visualization {
                flex: 1;
                position: relative;
            }
            
            #details-panel {
                height: 200px;
                padding: 15px;
                background-color: #f8f9fa;
                border-top: 1px solid #ddd;
                overflow-y: auto;
            }
            
            h3 {
                margin-top: 5px;
                margin-bottom: 10px;
            }
            
            .metric {
                margin-bottom: 8px;
            }
            
            .metric-value {
                font-weight: bold;
                float: right;
            }
            
            .chart-container {
                height: 150px;
                margin: 15px 0;
            }
            
            .category {
                background: white;
                margin-bottom: 8px;
                padding: 10px;
                border-radius: 6px;
                cursor: pointer;
            }
            
            .severity-badge {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 4px;
            }
            
            .high { background-color: #dc3545; }
            .medium { background-color: #fd7e14; }
            .low { background-color: #0dcaf0; }
            .info { background-color: #20c997; }
            
            #loading {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background-color: rgba(255,255,255,0.8);
                padding: 20px;
                border-radius: 5px;
                text-align: center;
            }
            
            .component-list {
                max-height: 300px;
                overflow-y: auto;
                margin-top: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            
            .component-item {
                padding: 8px;
                border-bottom: 1px solid #eee;
                cursor: pointer;
            }
            
            .component-item:hover {
                background-color: #f5f5f5;
            }
            
            .risk-meter {
                height: 8px;
                width: 100%;
                background-color: #e9ecef;
                border-radius: 4px;
                margin-bottom: 5px;
                overflow: hidden;
            }
            
            .risk-value {
                height: 100%;
                background-color: #fd7e14;
                border-radius: 4px;
            }
            
            .button-group {
                margin: 15px 0;
            }
            
            button {
                padding: 8px 12px;
                background-color: #4361ee;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                margin-right: 5px;
            }
            
            button:hover {
                background-color: #3a56d4;
            }
            
            .network-options {
                margin: 10px 0;
                background: white;
                padding: 10px;
                border-radius: 5px;
            }
            
            .connection-list {
                max-height: 200px;
                overflow-y: auto;
                margin-top: 10px;
                border: 1px solid #eee;
                padding: 5px;
                border-radius: 4px;
            }
            
            .toggle-button {
                margin-top: 10px;
                padding: 5px 10px;
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                border-radius: 3px;
                cursor: pointer;
            }
            
            .toggle-button:hover {
                background-color: #e6e6e6;
            }
        </style>
    </head>
    <body>
        <div id="left-panel">
            <h3>Attack Surface Overview</h3>
            
            <div style="background: white; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
                <div class="metric">Components <span class="metric-value" id="total-components">0</span></div>
                <div class="metric">Connections <span class="metric-value" id="total-connections">0</span></div>
                <div class="metric">Vulnerabilities <span class="metric-value" id="total-vulnerabilities">0</span></div>
            </div>
            
            <div style="background: white; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
                <h4 style="margin-top: 0;">Overall Risk Score: <span id="total-risk-score">0</span></h4>
                <div class="risk-meter">
                    <div class="risk-value" id="risk-meter-value" style="width: 0%"></div>
                </div>
                <div id="risk-level-text">Low Risk</div>
            </div>
            
            <div class="chart-container">
                <canvas id="severity-chart"></canvas>
            </div>
            
            <div class="button-group">
                <button id="show-core-btn">Show Core Components</button>
                <button id="show-high-risk-btn">Show High Risk</button>
            </div>
            
            <h3>Component Categories</h3>
            <div id="categories-container"></div>
            
            <h3>High Risk Components</h3>
            <div class="component-list" id="high-risk-components"></div>
        </div>
        
        <div id="right-panel">
            <div id="visualization">
                <div id="loading">Generating visualization (this may take a moment)...</div>
            </div>
            <div id="details-panel">
                <h3>Component Details</h3>
                <p>Select a component from the list or graph to view details.</p>
            </div>
        </div>
        
        <script>
            // Parse the embedded visualization data
            const visualizationData = VISUALIZATION_DATA_PLACEHOLDER;
            
            // Set metrics
            document.getElementById('total-components').textContent = visualizationData.metrics.total_components;
            document.getElementById('total-connections').textContent = visualizationData.metrics.total_connections;
            document.getElementById('total-vulnerabilities').textContent = visualizationData.metrics.total_vulnerabilities;
            
            const totalRiskScore = visualizationData.metrics.total_risk_score;
            document.getElementById('total-risk-score').textContent = totalRiskScore.toFixed(1);
            
            // Set risk meter
            const riskPercent = Math.min(100, (totalRiskScore / 1000) * 100);
            document.getElementById('risk-meter-value').style.width = riskPercent + '%';
            
            // Set risk level text
            let riskLevelText = "Low Risk";
            let riskColor = "#20c997";
            
            if (totalRiskScore > 500) {
                riskLevelText = "Critical Risk";
                riskColor = "#dc3545";
            } else if (totalRiskScore > 200) {
                riskLevelText = "High Risk";
                riskColor = "#fd7e14";
            } else if (totalRiskScore > 50) {
                riskLevelText = "Medium Risk";
                riskColor = "#ffc107";
            }
            
            document.getElementById('risk-level-text').textContent = riskLevelText;
            document.getElementById('risk-meter-value').style.backgroundColor = riskColor;
            
            // Create severity chart
            const severityCounts = {
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0,
                INFO: 0
            };
            
            // Calculate severity counts
            visualizationData.nodes.forEach(node => {
                Object.entries(node.severity_counts).forEach(([severity, count]) => {
                    severityCounts[severity] += count;
                });
            });
            
            const severityChartCtx = document.getElementById('severity-chart').getContext('2d');
            new Chart(severityChartCtx, {
                type: 'doughnut',
                data: {
                    labels: ['High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [
                            severityCounts.HIGH,
                            severityCounts.MEDIUM,
                            severityCounts.LOW,
                            severityCounts.INFO
                        ],
                        backgroundColor: [
                            '#dc3545',
                            '#fd7e14',
                            '#0dcaf0',
                            '#20c997'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    legend: {
                        display: false
                    }
                }
            });
            
            // Populate categories
            const categoriesContainer = document.getElementById('categories-container');
            Object.entries(visualizationData.categories).forEach(([key, category]) => {
                const categoryElement = document.createElement('div');
                categoryElement.className = 'category';
                categoryElement.setAttribute('data-category', key);
                categoryElement.innerHTML = `
                    <div><strong>${category.name}</strong> <span style="float:right">${category.count}</span></div>
                    <div>Risk: ${category.risk_score.toFixed(1)}</div>
                `;
                
                // Add click handler to show this category
                categoryElement.addEventListener('click', () => {
                    showCategoryComponents(key);
                });
                
                categoriesContainer.appendChild(categoryElement);
            });
            
            // Sort nodes by risk score
            const sortedNodes = [...visualizationData.nodes].sort((a, b) => b.risk_score - a.risk_score);
            
            // Display the top 50 high risk components
            const highRiskContainer = document.getElementById('high-risk-components');
            sortedNodes.slice(0, 50).forEach(node => {
                const componentItem = document.createElement('div');
                componentItem.className = 'component-item';
                componentItem.setAttribute('data-id', node.id);
                
                // Create severity indicators
                let severityIndicators = '';
                if (node.severity_counts.HIGH > 0) 
                    severityIndicators += `<span class="severity-badge high"></span>`;
                if (node.severity_counts.MEDIUM > 0) 
                    severityIndicators += `<span class="severity-badge medium"></span>`;
                if (node.severity_counts.LOW > 0) 
                    severityIndicators += `<span class="severity-badge low"></span>`;
                if (node.severity_counts.INFO > 0) 
                    severityIndicators += `<span class="severity-badge info"></span>`;
                
                componentItem.innerHTML = `
                    <div>${severityIndicators} ${node.label}</div>
                    <div style="font-size: 12px; color: #666;">Risk: ${node.risk_score.toFixed(1)} | 
                    Vulns: ${node.vulnerabilities}</div>
                `;
                
                // Add click handler to show details and highlight in graph
                componentItem.addEventListener('click', () => {
                    showComponentDetails(node);
                    highlightNode(node.id);
                });
                
                highRiskContainer.appendChild(componentItem);
            });
            
            // Network visualization variables
            let network = null;
            let nodes = new vis.DataSet();
            let edges = new vis.DataSet();
            
            // Color mapping for node types
            const typeColors = {
                'binary': '#4361ee',
                'library': '#7209b7',
                'config': '#f9c74f',
                'script': '#f8961e',
                'security': '#f94144',
                'web': '#4cc9f0',
                'other': '#90b4ce'
            };
            
            // Function to initialize network with nodes
            function initializeNetwork(selectedNodes) {
                // Clear existing network
                if (network !== null) {
                    network.destroy();
                    nodes.clear();
                    edges.clear();
                }
                
                document.getElementById('loading').style.display = 'block';
                document.getElementById('loading').textContent = 'Building component graph...';
                
                // Create nodes for the selected components
                const nodeIds = [];
                
                selectedNodes.forEach(node => {
                    // Get highest severity for color
                    let borderColor = '#aaa';
                    if (node.severity_counts.HIGH > 0) {
                        borderColor = '#dc3545';
                    } else if (node.severity_counts.MEDIUM > 0) {
                        borderColor = '#fd7e14';
                    } else if (node.severity_counts.LOW > 0) {
                        borderColor = '#0dcaf0';
                    } else if (node.severity_counts.INFO > 0) {
                        borderColor = '#20c997';
                    }
                    
                    nodes.add({
                        id: node.id,
                        label: node.label,
                        color: {
                            background: typeColors[node.type] || '#90b4ce',
                            border: borderColor
                        },
                        size: 10 + (node.risk_score / 10),
                        title: `${node.label} (Risk: ${node.risk_score.toFixed(1)})`,
                        data: node
                    });
                    
                    nodeIds.push(node.id);
                });
                
                // Create edges between the selected nodes
                visualizationData.edges.forEach(edge => {
                    if (nodeIds.includes(edge.source) && nodeIds.includes(edge.target)) {
                        edges.add({
                            from: edge.source,
                            to: edge.target,
                            arrows: 'to',
                            color: { color: '#aaa', opacity: 0.5 },
                            width: 0.5,
                            title: edge.type
                        });
                    }
                });
                
                // Create the network
                const container = document.getElementById('visualization');
                const data = {
                    nodes: nodes,
                    edges: edges
                };
                
                const options = {
                    nodes: {
                        shape: 'dot',
                        font: {
                            size: 12
                        }
                    },
                    edges: {
                        width: 0.5,
                        smooth: {
                            type: 'continuous'
                        }
                    },
                    physics: {
                        stabilization: {
                            iterations: 100
                        },
                        barnesHut: {
                            gravitationalConstant: -2000,
                            centralGravity: 0.1,
                            springLength: 95,
                            springConstant: 0.04
                        }
                    },
                    interaction: {
                        tooltipDelay: 200,
                        hideEdgesOnDrag: true,
                        navigationButtons: true,
                        keyboard: true
                    }
                };
                
                network = new vis.Network(container, data, options);
                
                network.on('stabilizationProgress', function(params) {
                    document.getElementById('loading').textContent = 
                        `Stabilizing: ${Math.round(params.iterations / params.total * 100)}%`;
                });
                
                network.on('stabilizationIterationsDone', function() {
                    document.getElementById('loading').style.display = 'none';
                });
                
                network.on('click', function(params) {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        const nodeData = nodes.get(nodeId).data;
                        showComponentDetails(nodeData);
                    }
                });
            }
            
            // Function to show component details
            function showComponentDetails(node) {
                const detailsPanel = document.getElementById('details-panel');
                
                // Create severity indicators
                let vulnerabilitySummary = '';
                if (node.severity_counts.HIGH > 0) 
                    vulnerabilitySummary += `<span class="severity-badge high"></span>${node.severity_counts.HIGH} High `;
                if (node.severity_counts.MEDIUM > 0) 
                    vulnerabilitySummary += `<span class="severity-badge medium"></span>${node.severity_counts.MEDIUM} Medium `;
                if (node.severity_counts.LOW > 0) 
                    vulnerabilitySummary += `<span class="severity-badge low"></span>${node.severity_counts.LOW} Low `;
                if (node.severity_counts.INFO > 0) 
                    vulnerabilitySummary += `<span class="severity-badge info"></span>${node.severity_counts.INFO} Info`;
                
                if (!vulnerabilitySummary) vulnerabilitySummary = 'None';
                
                // Find connected components
                const connections = {
                    incoming: [],
                    outgoing: []
                };
                
                // Find direct connections
                visualizationData.edges.forEach(edge => {
                    if (edge.source === node.id) {
                        const target = visualizationData.nodes.find(n => n.id === edge.target);
                        if (target) {
                            connections.outgoing.push({
                                node: target,
                                type: edge.type || 'connects to'
                            });
                        }
                    } else if (edge.target === node.id) {
                        const source = visualizationData.nodes.find(n => n.id === edge.source);
                        if (source) {
                            connections.incoming.push({
                                node: source,
                                type: edge.type || 'connects from'
                            });
                        }
                    }
                });
                
                // Sort connections by risk score
                connections.incoming.sort((a, b) => b.node.risk_score - a.node.risk_score);
                connections.outgoing.sort((a, b) => b.node.risk_score - a.node.risk_score);
                
                // Create connections HTML
                let connectionsHTML = '';
                let hasConnections = connections.incoming.length > 0 || connections.outgoing.length > 0;
                
                if (hasConnections) {
                    connectionsHTML = '<div class="connection-list">';
                    
                    if (connections.incoming.length > 0) {
                        connectionsHTML += `<strong>Incoming (${connections.incoming.length}):</strong><ul>`;
                        connections.incoming.slice(0, 5).forEach(conn => {
                            connectionsHTML += `
                                <li>
                                    <a href="#" onclick="highlightNode('${conn.node.id}'); return false;">
                                        ${conn.node.label}
                                    </a> 
                                    (${conn.type}, Risk: ${conn.node.risk_score.toFixed(1)})
                                </li>`;
                        });
                        if (connections.incoming.length > 5) {
                            connectionsHTML += `<li>...and ${connections.incoming.length - 5} more</li>`;
                        }
                        connectionsHTML += '</ul>';
                    }
                    
                    if (connections.outgoing.length > 0) {
                        connectionsHTML += `<strong>Outgoing (${connections.outgoing.length}):</strong><ul>`;
                        connections.outgoing.slice(0, 5).forEach(conn => {
                            connectionsHTML += `
                                <li>
                                    <a href="#" onclick="highlightNode('${conn.node.id}'); return false;">
                                        ${conn.node.label}
                                    </a> 
                                    (${conn.type}, Risk: ${conn.node.risk_score.toFixed(1)})
                                </li>`;
                        });
                        if (connections.outgoing.length > 5) {
                            connectionsHTML += `<li>...and ${connections.outgoing.length - 5} more</li>`;
                        }
                        connectionsHTML += '</ul>';
                    }
                    
                    connectionsHTML += '</div>';
                    connectionsHTML += `
                        <div class="toggle-button" id="show-connections-btn">
                            Show in graph
                        </div>`;
                }
                
                detailsPanel.innerHTML = `
                    <h3>${node.label}</h3>
                    <div style="background: white; padding: 10px; border-radius: 5px; margin-bottom: 10px;">
                        <div><strong>Path:</strong> ${node.full_path}</div>
                        <div><strong>Type:</strong> ${node.type}</div>
                        <div><strong>Category:</strong> ${node.category}</div>
                        <div><strong>Risk Score:</strong> ${node.risk_score.toFixed(2)}</div>
                        <div><strong>Vulnerabilities:</strong> ${vulnerabilitySummary}</div>
                        <div><strong>Connections:</strong> ${connections.incoming.length + connections.outgoing.length}</div>
                    </div>
                    ${hasConnections ? '<h4>Connections:</h4>' + connectionsHTML : ''}
                `;
                
                // Add event listener to the show connections button
                if (hasConnections) {
                    document.getElementById('show-connections-btn').addEventListener('click', function() {
                        showComponentConnections(node);
                    });
                }
            }
            
            // Function to show component connections
            function showComponentConnections(centerNode) {
                // Find direct connections
                const connectedNodes = [centerNode];
                
                // Get directly connected nodes
                visualizationData.edges.forEach(edge => {
                    if (edge.source === centerNode.id) {
                        const target = visualizationData.nodes.find(n => n.id === edge.target);
                        if (target && !connectedNodes.some(n => n.id === target.id)) {
                            connectedNodes.push(target);
                        }
                    } else if (edge.target === centerNode.id) {
                        const source = visualizationData.nodes.find(n => n.id === edge.source);
                        if (source && !connectedNodes.some(n => n.id === source.id)) {
                            connectedNodes.push(source);
                        }
                    }
                });
                
                // Initialize network with connected nodes
                initializeNetwork(connectedNodes);
                
                // Highlight the center node
                setTimeout(() => {
                    highlightNode(centerNode.id);
                }, 1000);
            }
            
            // Function to show components of a category
            function showCategoryComponents(category) {
                const categoryNodes = visualizationData.nodes.filter(node => node.category === category);
                
                // Sort by risk score
                categoryNodes.sort((a, b) => b.risk_score - a.risk_score);
                
                // Take top 30 by risk score
                const nodesToShow = categoryNodes.slice(0, 30);
                
                // Initialize network with category nodes
                initializeNetwork(nodesToShow);
            }
            
            // Function to highlight a node in the network
            window.highlightNode = function(nodeId) {
                if (network) {
                    network.selectNodes([nodeId]);
                    network.focus(nodeId, {
                        scale: 1.5,
                        animation: true
                    });
                    
                    // Find the node data
                    const nodeData = visualizationData.nodes.find(n => n.id === nodeId);
                    if (nodeData) {
                        showComponentDetails(nodeData);
                    }
                }
            };
            
            // Button event listeners
            document.getElementById('show-core-btn').addEventListener('click', function() {
                const coreNodes = visualizationData.nodes.filter(node => node.category === 'core');
                initializeNetwork(coreNodes.slice(0, 30));
            });
            
            document.getElementById('show-high-risk-btn').addEventListener('click', function() {
                initializeNetwork(sortedNodes.slice(0, 30));
            });
            
            // Initialize with high risk components
            initializeNetwork(sortedNodes.slice(0, 30));
        </script>
    </body>
    </html>
    """
    
    # Convert visualization data to JSON for embedding in HTML
    import json
    visualization_json = json.dumps(visualization_data)
    
    # Replace placeholder with actual data
    html_content = html_template.replace('VISUALIZATION_DATA_PLACEHOLDER', visualization_json)
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"Attack surface visualization exported to {output_file}")
    return output_file
                       
def main():
    global use_colors, show_all, verbose, findings
    
    parser = argparse.ArgumentParser(description='Firmware Vulnerability Scanner')
    parser.add_argument('firmware_root', help='Path to the extracted firmware root directory')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--all', action='store_true', help='Show all findings, not just a sample')
    parser.add_argument('--html', help='Export results to HTML file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show more detailed errors')
    # Add new argument for intersection analysis
    parser.add_argument('--analyze-intersections', action='store_true', 
                        help='Analyze intersection points of multiple vulnerabilities')
    parser.add_argument('--intersection-report', default='vulnerability_intersections.html',
                        help='Path to save vulnerability intersections report')
    # Add new arguments for attack surface visualization
    parser.add_argument('--visualize-attack-surface', action='store_true',
                       help='Generate a visualization of firmware attack surface')
    parser.add_argument('--visualization-file', default='attack_surface.html',
                       help='Path to save attack surface visualization')
    parser.add_argument('--recommend-patches', action='store_true', 
                        help='Generate patch recommendations for identified vulnerabilities')
    parser.add_argument('--recommendations-html', default='vulnerability_recommendations.html',
                        help='Path to save vulnerability remediation recommendations to HTML')
    
    args = parser.parse_args()
    
    use_colors = not args.no_color
    show_all = args.all
    verbose = args.verbose
    
    firmware_root = args.firmware_root
    if not os.path.isdir(firmware_root):
        print(f"Error: {firmware_root} is not a directory")
        sys.exit(1)
    
    print(f"Scanning {firmware_root} for vulnerabilities...")
    
    # Run all checks
    check_passwd_shadow(firmware_root)
    check_config_files(firmware_root)
    check_scripts(firmware_root)
    check_private_keys(firmware_root)
    check_dangerous_functions(firmware_root)
    
    # Print findings
    print_findings()

    # Initialize recommendations to None
    recommendations = None

    # Only generate patch recommendations if requested
    if args.recommend_patches:
        print("\nGenerating patch recommendations...")
        recommendations = recommend_patches(findings)
        print_patch_recommendations(recommendations)

    # Only export recommendations if they were generated
    if args.recommendations_html:
        if recommendations is not None:
            export_recommendations_to_html(recommendations, args.recommendations_html)
            print(f"Patch recommendations exported to {args.recommendations_html}")
        else:
            print("Cannot export recommendations: No recommendations were generated. Use --recommend-patches option.")
    
    # Generate intersection analysis if requested
    if args.analyze_intersections:
        print("Analyzing vulnerability intersection points...")
        # Make sure this function is defined elsewhere in your code
        intersections = analyze_vulnerability_intersections(findings, firmware_root)
        
        if intersections:
            intersection_report = export_intersections_to_html(intersections, args.intersection_report)
            print(f"Generated intersection report: {intersection_report}")
            print(f"Found {len(intersections)} files with multiple vulnerabilities.")
            
            # Print top 3 intersection points to console
            if len(intersections) > 0:
                print("\nTop critical intersection points:")
                for i, intersection in enumerate(intersections[:3]):
                    print(f"  {i+1}. {intersection['file_path']}")
                    print(f"     - {intersection['count']} vulnerabilities, Risk Score: {intersection['risk_score']:.1f}")
                    print(f"     - Highest severity: {intersection['highest_severity']}")
        else:
            print("No vulnerability intersection points found.")
    
    # Generate attack surface visualization if requested
    if args.visualize_attack_surface:
        print("Generating firmware attack surface visualization...")
        visualization_data = analyze_firmware_components(firmware_root, findings)
        
        if visualization_data:
            visualization_file = export_visualization_to_html(visualization_data, args.visualization_file)
            print(f"Generated attack surface visualization: {visualization_file}")
            print("Open this file in a web browser to explore the attack surface.")
    
    # Export HTML report if requested
    if args.html:
        export_findings_to_html(args.html)
    
    print("\nScan complete!")

if __name__ == "__main__":
    main()
