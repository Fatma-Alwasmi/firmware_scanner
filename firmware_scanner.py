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
                    # Try to use objdump to get symbol information with addresses
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

                       
def main():
    global use_colors, show_all, verbose, findings
    
    parser = argparse.ArgumentParser(description='Firmware Vulnerability Scanner')
    parser.add_argument('firmware_root', help='Path to the extracted firmware root directory')
    parser.add_argument('--all', action='store_true', help='Show all findings, not just a sample')
    parser.add_argument('--html', help='Export results to HTML file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show more detailed errors')
    parser.add_argument('--recommend-patches', default='vulnerability_recommendations.html', 
                        help='Generate patch recommendations for identified vulnerabilities')
    
    args = parser.parse_args()
    
    # use_colors = not args.no_color
    # show_all = args.all
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
        if recommendations is not None:
            export_recommendations_to_html(recommendations, args.recommend_patches)
            print(f"Patch recommendations exported to {args.recommend_patches}")
        else:
            print("Cannot export recommendations: No recommendations were generated. Use --recommend-patches option.")
        print_patch_recommendations(recommendations)

    if args.html:
        export_findings_to_html(args.html)
    
    print("\nScan complete!")

if __name__ == "__main__":
    main()