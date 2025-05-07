#!/usr/bin/env python3
"""
Vulnerability Patch Recommender Module
This module recommends real-world patches for vulnerabilities found in firmware.
"""

import os
import re
import json
import subprocess
from collections import defaultdict

# Patch recommendations database 
# Maps vulnerability types to recommended fixes with examples
PATCH_RECOMMENDATIONS = {
    "DANGEROUS_FUNCTION": {
        "strcpy": {
            "title": "Replace strcpy with safer alternatives",
            "description": "strcpy is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with strncpy, strlcpy, or strcpy_s to prevent buffer overflows.",
            "before_patch": "char buffer[10];\nstrcpy(buffer, source); // Dangerous - no bounds checking",
            "after_patch": "char buffer[10];\nstrncpy(buffer, source, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0'; // Ensure null termination",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/scriptingxss/embeddedappsec/blob/master/1_buffer_and_stack_overflow_protection.md"
            ],
            "real_world_examples": [
                {"cve": "CVE-2021-3156", "description": "Heap-based buffer overflow in Sudo ('Baron Samedit')"}
            ]
        },
        "strcat": {
            "title": "Replace strcat with safer alternatives",
            "description": "strcat is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with strncat or strlcat to prevent buffer overflows.",
            "before_patch": "char buffer[10];\nstrcat(buffer, source); // Dangerous - no bounds checking",
            "after_patch": "char buffer[10];\nstrncat(buffer, source, sizeof(buffer) - strlen(buffer) - 1); // Safe version with bounds checking",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/scriptingxss/embeddedappsec/blob/master/1_buffer_and_stack_overflow_protection.md"
            ]
        },
        "sprintf": {
            "title": "Replace sprintf with safer alternatives",
            "description": "sprintf is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with snprintf to prevent buffer overflows.",
            "before_patch": "char buffer[50];\nsprintf(buffer, \"%s %d\", str, num); // Dangerous - no bounds checking",
            "after_patch": "char buffer[50];\nsnprintf(buffer, sizeof(buffer), \"%s %d\", str, num); // Safe version with bounds checking",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/samtools/htslib/issues/1586"
            ],
            "real_world_examples": [
                {"project": "htslib", "description": "Switch from sprintf to snprintf for security improvement"}
            ]
        },
        "gets": {
            "title": "Replace gets with safer alternatives",
            "description": "gets is extremely unsafe and has been deprecated - it has no way to limit input length.",
            "recommendation": "Replace with fgets which allows for specifying the buffer size.",
            "before_patch": "char buffer[100];\ngets(buffer); // Very dangerous - no bounds checking at all",
            "after_patch": "char buffer[100];\nfgets(buffer, sizeof(buffer), stdin); // Safe version with bounds checking",
            "references": [
                "CWE-242: Use of Inherently Dangerous Function",
                "https://www.fortinet.com/resources/cyberglossary/buffer-overflow"
            ]
        },
        "memcpy": {
            "title": "Use memcpy with proper bounds checking",
            "description": "memcpy is unsafe when the source size exceeds the destination buffer.",
            "recommendation": "Always validate the source size against destination buffer size.",
            "before_patch": "char buffer[10];\nmemcpy(buffer, source, len); // Dangerous if len > sizeof(buffer)",
            "after_patch": "char buffer[10];\nif (len <= sizeof(buffer)) {\n    memcpy(buffer, source, len);\n} else {\n    // Handle error or truncate\n    memcpy(buffer, source, sizeof(buffer));\n}",
            "references": [
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer"
            ]
        }
    },
    "HARDCODED_CREDENTIAL": {
        "general": {
            "title": "Remove hardcoded credentials",
            "description": "Hardcoded credentials are a serious security risk as they can be extracted from firmware.",
            "recommendation": "Store credentials securely using a secure storage mechanism or environment variables.",
            "before_patch": "const char* password = \"hardcoded_password\"; // Dangerous",
            "after_patch": "const char* password = get_password_from_secure_storage(); // Better approach",
            "references": [
                "CWE-798: Use of Hard-coded Credentials",
                "https://cwe.mitre.org/data/definitions/798.html"
            ]
        },
        "config": {
            "title": "Remove hardcoded credentials from configuration",
            "description": "Hardcoded credentials and keys in configuration files are easy to extract from firmware.",
            "recommendation": "Use environment variables, secure key storage, or runtime configuration to supply sensitive values.",
            "before_patch": "# Configuration file with hardcoded credentials\npassword=admin123\nkey=/etc/keys/private.key\ncert=/etc/certs/server.crt",
            "after_patch": "# Secure configuration using environment variables\npassword=${SECURE_PASSWORD}\nkey=${KEY_PATH}\ncert=${CERT_PATH}\n\n# Alternatively, use a secure credential management system",
            "references": [
                "CWE-798: Use of Hard-coded Credentials",
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"
            ]
        },
        "key": {
            "title": "Secure key and certificate storage",
            "description": "Hardcoded paths to keys and certificates in configuration files can expose sensitive cryptographic material.",
            "recommendation": "Use secure key management, relative paths with restricted permissions, or environment variables for key paths.",
            "before_patch": "# Hardcoded key paths in config\nkey=/etc/stunnel/stunnel.pem\ncert=/etc/stunnel/server.crt",
            "after_patch": "# More secure key handling\nkey=${KEY_FILE_PATH}\ncert=${CERT_FILE_PATH}\n\n# With proper permissions on files and directories\n# chmod 600 ${KEY_FILE_PATH}",
            "references": [
                "CWE-798: Use of Hard-coded Credentials",
                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"
            ]
        }
    },
    "INSECURE_HTTP": {
        "http": {
            "title": "Replace HTTP with HTTPS",
            "description": "Unencrypted HTTP connections expose data in transit to eavesdropping.",
            "recommendation": "Use HTTPS instead of HTTP for all connections to ensure encryption.",
            "before_patch": "url = \"http://example.com/api\"; // Unencrypted connection",
            "after_patch": "url = \"https://example.com/api\"; // Encrypted connection",
            "references": [
                "CWE-319: Cleartext Transmission of Sensitive Information"
            ]
        }
    },
    "AUTH_DISABLED": {
        "general": {
            "title": "Enable authentication",
            "description": "Disabled authentication allows unauthorized access to the system.",
            "recommendation": "Always enable authentication mechanisms, especially for sensitive operations.",
            "before_patch": "auth_enabled = false; // Authentication disabled",
            "after_patch": "auth_enabled = true; // Authentication enabled",
            "references": [
                "CWE-306: Missing Authentication for Critical Function"
            ]
        }
    },
    "EMPTY_PASSWORD": {
        "general": {
            "title": "Enforce password requirements",
            "description": "Empty passwords provide no security and allow easy unauthorized access.",
            "recommendation": "Implement password policies that enforce minimum complexity and length.",
            "before_patch": "if (password == \"\") { // Accepts empty password\n    grant_access();\n}",
            "after_patch": "if (is_valid_password(password)) { // Checks password strength\n    grant_access();\n}",
            "references": [
                "CWE-521: Weak Password Requirements"
            ]
        }
    },
    "WEAK_PASSWORD_HASH": {
        "general": {
            "title": "Use secure password hashing",
            "description": "Weak hashing algorithms are vulnerable to brute force attacks.",
            "recommendation": "Use strong modern hashing algorithms like bcrypt, Argon2, or PBKDF2.",
            "before_patch": "password_hash = md5(password); // Weak hashing",
            "after_patch": "password_hash = bcrypt(password, salt, cost_factor); // Strong hashing",
            "references": [
                "CWE-916: Use of Password Hash With Insufficient Computational Effort"
            ]
        }
    },
    "POSSIBLE_COMMAND_INJECTION": {
        "general": {
            "title": "Prevent command injection",
            "description": "Unsanitized user input passed to system commands allows code execution.",
            "recommendation": "Avoid using system commands with user input. If necessary, whitelist allowed inputs or use safe APIs.",
            "before_patch": "system(\"ping \" + user_input); // Vulnerable to injection",
            "after_patch": "// Use validation and sanitization\nif (is_valid_hostname(user_input)) {\n    system(\"ping \" + sanitize_input(user_input));\n}",
            "references": [
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
            ]
        },
        "bash": {
            "title": "Modernize shell script command substitution",
            "description": "Command substitution with backticks is outdated but not necessarily vulnerable in system scripts.",
            "recommendation": "Consider using $(command) syntax instead of backticks for better nesting and readability. Only validate input if it comes from untrusted sources.",
            "before_patch": "# Command substitution with backticks\nport=`/usr/sbin/userconfig -read RTSP Port`\nkill `pidof rtspd`",
            "after_patch": "# Modern command substitution syntax\nport=$(/usr/sbin/userconfig -read RTSP Port)\nkill $(pidof rtspd)",
            "references": [
                "https://www.shellcheck.net/wiki/SC2006"
            ]
        }
    },
    "PRIVATE_KEY_FILE": {
        "general": {
            "title": "Secure private key storage",
            "description": "Exposed private keys in firmware can be extracted and compromised.",
            "recommendation": "Store private keys in a secure element or trusted platform module if available.",
            "before_patch": "// Private key stored in plaintext file\nkey = load_file(\"/etc/private.key\")",
            "after_patch": "// Key stored in secure element\nkey = secure_element.get_key(\"private_key_id\")",
            "references": [
                "CWE-321: Use of Hard-coded Cryptographic Key"
            ]
        }
    },

    "DEFAULT_ACCOUNT": {
        "general": {
            "title": "Remove or secure default accounts",
            "description": "Default accounts provide attackers with known entry points into the system, especially if they have privileged access (root/admin).",
            "recommendation": "Remove unnecessary default accounts or implement proper account management: change default passwords, restrict privileges, and implement proper authentication controls.",
            "before_patch": "# /etc/passwd entry with default root account\nadmin::0:0:root:/:/bin/sh\nroot:x:0:0:root:/root:/bin/bash",
            "after_patch": "# Proper account with non-empty password hash and limited privileges\nadmin:x:1000:1000:System Admin:/home/admin:/bin/sh\n\n# For firmware initialization, consider using a first-boot setup that forces password change",
            "references": [
                "CWE-255: Credentials Management Errors",
                "CWE-250: Execution with Unnecessary Privileges",
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
            ]
        }
    },

    "EMPTY_PASSWORD": {
        "general": {
            "title": "Eliminate empty passwords",
            "description": "Empty passwords provide no security and allow unauthorized access to the system.",
            "recommendation": "Implement proper password management: enforce non-empty passwords, use secure password hashing, and implement account lockout mechanisms.",
            "before_patch": "# /etc/passwd or /etc/shadow entry with empty password\nuser::1000:1000:User:/home/user:/bin/sh\n# or\nuser::18640:0:99999:7:::",
            "after_patch": "# Proper account with password hash\nuser:$6$salt$hashedpassword:1000:1000:User:/home/user:/bin/sh\n# or\nuser:$6$salt$hashedpassword:18640:0:99999:7:::",
            "references": [
                "CWE-521: Weak Password Requirements",
                "CWE-262: Not Using Password Aging",
                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
            ]
        }
    },

    "ROOT_ACCOUNT": {
        "general": {
            "title": "Secure root accounts and limit privileged access",
            "description": "Root accounts (UID 0) have unlimited system access and pose a significant security risk if compromised.",
            "recommendation": "Limit the number of root accounts, ensure proper authentication, use sudo for privilege escalation, and implement the principle of least privilege.",
            "before_patch": "# Multiple accounts with root privileges\nroot:x:0:0:root:/root:/bin/bash\nadmin::0:0:admin:/home/admin:/bin/sh\nsupport:x:0:0:support:/home/support:/bin/sh",
            "after_patch": "# Single root account with proper password and limited-privilege accounts\nroot:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\nsupport:x:1001:1001:support:/home/support:/bin/sh\n\n# And in /etc/sudoers:\nadmin ALL=(ALL) ALL\nsupport ALL=(ALL:ALL) /bin/systemctl restart network",
            "references": [
                "CWE-250: Execution with Unnecessary Privileges",
                "CWE-272: Least Privilege Violation",
                "https://csrc.nist.gov/publications/detail/sp/800-190/final"
            ]
        }
    }
}

def get_binary_function_recommendations(findings_list):
    """
    Generate function-specific recommendations for all dangerous functions found in a binary.
    
    Args:
        findings_list: List of finding strings containing dangerous function references
        
    Returns:
        List of recommendation dictionaries for each identified dangerous function
    """
    # Dictionary mapping dangerous functions to their safe alternatives
    function_recommendations = {
        "strcpy": {
            "title": "Replace strcpy with safer alternatives",
            "description": "strcpy is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with strncpy, strlcpy, or strcpy_s to prevent buffer overflows.",
            "before_patch": "char buffer[10];\nstrcpy(buffer, source); // Dangerous - no bounds checking",
            "after_patch": "char buffer[10];\nstrncpy(buffer, source, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0'; // Ensure null termination",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/scriptingxss/embeddedappsec/blob/master/1_buffer_and_stack_overflow_protection.md"
            ],
            "real_world_examples": [
                {"cve": "CVE-2021-3156", "description": "Heap-based buffer overflow in Sudo ('Baron Samedit')"}
            ]
        },
        "strcat": {
            "title": "Replace strcat with safer alternatives",
            "description": "strcat is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with strncat to prevent buffer overflows.",
            "before_patch": "char buffer[10];\nstrcat(buffer, suffix); // Dangerous - no bounds checking",
            "after_patch": "char buffer[10];\nstrncat(buffer, suffix, sizeof(buffer) - strlen(buffer) - 1); // Safe version with bounds checking",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/scriptingxss/embeddedappsec/blob/master/1_buffer_and_stack_overflow_protection.md"
            ],
            "real_world_examples": [
                {"cve": "CVE-2020-3283", "description": "Buffer overflow vulnerability in Cisco AnyConnect"}
            ]
        },
        "sprintf": {
            "title": "Replace sprintf with safer alternatives",
            "description": "sprintf is unsafe because it does not perform bounds checking, which can lead to buffer overflows.",
            "recommendation": "Replace with snprintf to prevent buffer overflows.",
            "before_patch": "char buffer[50];\nsprintf(buffer, \"%s %d\", str, num); // Dangerous - no bounds checking",
            "after_patch": "char buffer[50];\nsnprintf(buffer, sizeof(buffer), \"%s %d\", str, num); // Safe version with bounds checking",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://github.com/samtools/htslib/issues/1586"
            ],
            "real_world_examples": [
                {"cve": "CVE-2019-19726", "description": "Buffer overflow in OpenBSD's ftp program via sprintf"}
            ]
        },
        "gets": {
            "title": "Replace gets with safer alternatives",
            "description": "gets is extremely unsafe and has been deprecated - it has no way to limit input length.",
            "recommendation": "Replace with fgets which allows for specifying the buffer size.",
            "before_patch": "char buffer[100];\ngets(buffer); // Very dangerous - no bounds checking at all",
            "after_patch": "char buffer[100];\nfgets(buffer, sizeof(buffer), stdin); // Safe version with bounds checking",
            "references": [
                "CWE-242: Use of Inherently Dangerous Function",
                "https://stackoverflow.com/questions/1694036/why-is-the-gets-function-dangerous-why-should-it-not-be-used"
            ],
            "real_world_examples": [
                {"cve": "CVE-2018-11324", "description": "Buffer overflow in FTP server using gets"}
            ]
        },
        "system": {
            "title": "Avoid or secure system() calls",
            "description": "system() can lead to command injection vulnerabilities if user input is included in the command.",
            "recommendation": "Use more specific APIs instead, or if system() is necessary, carefully validate and sanitize all input.",
            "before_patch": "system(\"ping \" + user_input); // Vulnerable to command injection",
            "after_patch": "// Better approach - use specific API\ninet_addr_t addr = inet_addr(user_input); // Validate as IP address\nif (addr != INADDR_NONE) {\n    ping_host(addr); // Call a safer specific API instead\n}",
            "references": [
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
                "https://owasp.org/www-community/attacks/Command_Injection"
            ],
            "real_world_examples": [
                {"cve": "CVE-2021-4034", "description": "Polkit's pkexec command injection (PwnKit vulnerability)"}
            ]
        },
        "exec": {
            "title": "Secure exec function calls",
            "description": "exec family functions can lead to command injection if user input is included.",
            "recommendation": "Validate and sanitize all input, use execv/execve with explicit arguments rather than execl/execlp with shell interpretation.",
            "before_patch": "execl(\"/bin/sh\", \"sh\", \"-c\", cmd, NULL); // Vulnerable to command injection",
            "after_patch": "char *args[] = {\"/bin/program\", \"arg1\", \"arg2\", NULL};\nexecv(\"/bin/program\", args); // Safer - no shell interpretation",
            "references": [
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
                "https://wiki.sei.cmu.edu/confluence/display/c/POS36-C.+Observe+correct+revocation+order+with+exec+functions"
            ],
            "real_world_examples": [
                {"cve": "CVE-2020-12826", "description": "QEMU exec function leading to privilege escalation"}
            ]
        },
        "fork": {
            "title": "Handle fork() securely",
            "description": "fork() can lead to resource issues if not properly handled.",
            "recommendation": "Always check fork() return values, handle error cases, and ensure proper cleanup in both parent and child processes.",
            "before_patch": "fork(); // No return value check or error handling",
            "after_patch": "pid_t pid = fork();\nif (pid < 0) {\n    // Error handling\n    perror(\"fork failed\");\n    exit(EXIT_FAILURE);\n} else if (pid == 0) {\n    // Child process code\n    // Proper cleanup when done\n} else {\n    // Parent process code\n    // Proper cleanup when done\n}",
            "references": [
                "CWE-404: Improper Resource Shutdown or Release",
                "https://linux.die.net/man/2/fork"
            ]
        },
        "daemon": {
            "title": "Secure daemon process creation",
            "description": "daemon() function can create background processes that are difficult to track and manage.",
            "recommendation": "Follow proper daemon creation practices, including proper privilege dropping, resource limiting, and signal handling.",
            "before_patch": "daemon(0, 0); // Simple daemon with no security controls",
            "after_patch": "// Proper daemon implementation\ndaemon(0, 0);\n// Drop privileges after initialization\nif (setgid(UNPRIVILEGED_GID) != 0 || setuid(UNPRIVILEGED_UID) != 0) {\n    syslog(LOG_ERR, \"Failed to drop privileges\");\n    exit(EXIT_FAILURE);\n}\n// Set resource limits\nstruct rlimit limit;\nlimit.rlim_cur = limit.rlim_max = 64;\nsetrlimit(RLIMIT_NOFILE, &limit);",
            "references": [
                "CWE-250: Execution with Unnecessary Privileges",
                "https://man7.org/linux/man-pages/man3/daemon.3.html"
            ]
        },
        "memcpy": {
            "title": "Use memcpy with proper bounds checking",
            "description": "memcpy is unsafe when the source size exceeds the destination buffer.",
            "recommendation": "Always validate the source size against destination buffer size.",
            "before_patch": "char buffer[10];\nmemcpy(buffer, source, len); // Dangerous if len > sizeof(buffer)",
            "after_patch": "char buffer[10];\nif (len <= sizeof(buffer)) {\n    memcpy(buffer, source, len);\n} else {\n    // Handle error or truncate\n    memcpy(buffer, source, sizeof(buffer));\n}",
            "references": [
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "https://wiki.sei.cmu.edu/confluence/display/c/ARR38-C.+Guarantee+that+library+functions+do+not+form+invalid+pointers"
            ],
            "real_world_examples": [
                {"cve": "CVE-2019-0708", "description": "BlueKeep vulnerability in Windows RDP using unchecked memcpy"}
            ]
        },
        "scanf": {
            "title": "Replace scanf with safer alternatives",
            "description": "scanf can lead to buffer overflows if format specifiers don't limit input length.",
            "recommendation": "Use fgets to read input, then parse it with sscanf with field width limits.",
            "before_patch": "char buffer[10];\nscanf(\"%s\", buffer); // Dangerous - no length limit for %s",
            "after_patch": "char buffer[10];\nfgets(buffer, sizeof(buffer), stdin);\n// Remove newline if present\nchar *newline = strchr(buffer, '\\n');\nif (newline) *newline = '\\0';\n// Parse with sscanf if needed\nint value;\nsscanf(buffer, \"%d\", &value);",
            "references": [
                "CWE-120: Buffer Copy without Checking Size of Input",
                "https://wiki.sei.cmu.edu/confluence/display/c/FIO19-C.+Do+not+use+fsetpos%28%29+or+fsetpos%28%29+to+set+a+file+position+to+a+negative+value"
            ],
            "real_world_examples": [
                {"cve": "CVE-2018-5767", "description": "Buffer overflow in Firefox via scanf"}
            ]
        },
        "popen": {
            "title": "Secure popen() usage to prevent command injection",
            "description": "popen() executes commands with /bin/sh, making it vulnerable to command injection if used with unsanitized input.",
            "recommendation": "Validate all input used in popen() commands, use more specific APIs if possible, or use safer alternatives like execve() that don't invoke the shell.",
            "before_patch": "FILE *fp = popen(user_command, \"r\"); // Vulnerable to command injection",
            "after_patch": "// Validate input\nif (is_valid_command(user_command)) {\n    FILE *fp = popen(sanitize_command(user_command), \"r\");\n    // ...\n} else {\n    // Handle error\n}",
            "references": [
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
                "https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems"
            ],
            "real_world_examples": [
                {"cve": "CVE-2019-7304", "description": "Command injection vulnerability in snapd using popen()"}
            ]
        },
        
    }
    
    # Extract function names from findings
    found_functions = set()
    
    # Debug: Print the findings for inspection
    #print(f"Processing {len(findings_list)} findings:")
    #for f in findings_list:
    #    print(f"  - {f}")
    
    for finding in findings_list:
        if not finding:
            continue
            
        finding = finding.strip()
        if finding.startswith('* '):
            finding = finding[2:]
        
        # Improve the regex pattern to extract function names
        import re
        match = re.search(r"'([^']+)'", finding)
        if match:
            # Extract the full function name between quotes
            full_func_name = match.group(1).strip()
            
            # Extract the base function name (strip any prefixes or suffixes)
            base_func_name = re.sub(r'^_+', '', full_func_name)  # Remove leading underscores
            base_func_name = re.sub(r'@.*$', '', base_func_name)  # Remove @ suffix
            
            # For each known dangerous function, check if it appears in the extracted name
            for known_func in function_recommendations.keys():
                # Use word boundary to avoid partial matches
                if known_func == base_func_name or \
                   known_func == base_func_name.split('_')[-1] or \
                   known_func in base_func_name and len(known_func) > 3:  # Only match if significant part of name
                    found_functions.add(known_func)
                    #print(f"Matched '{known_func}' in '{full_func_name}'")
    
    # Debug: Print identified functions
    #print(f"Identified functions: {found_functions}")
    
    # Build recommendations for all found functions
    all_recommendations = []
    for func in sorted(found_functions):  # Sort for consistent ordering
        if func in function_recommendations:
            all_recommendations.append(function_recommendations[func])
    
    # Debug: Print number of recommendations
    #print(f"Generated {len(all_recommendations)} recommendations")
    
    return all_recommendations
    
def generate_custom_bash_example(findings_list):
    """Generate customized before/after examples based on actual findings.
    
    Args:
        findings_list: List of finding strings containing backtick commands
        
    Returns:
        Tuple of (before_example, after_example) with realistic code snippets
    """
    # Get up to 3 actual examples from findings
    examples = []
    for finding in findings_list[:3]:  # Limit to 3 examples for readability
        # Strip leading/trailing whitespace and any common prefix patterns
        clean_finding = finding.strip()
        if clean_finding.startswith('* '):
            clean_finding = clean_finding[2:]
        examples.append(clean_finding)
    
    if not examples:
        # Fallback to generic example if no findings
        return (
            "# Command substitution with backticks\n" +
            "port=`/usr/sbin/userconfig -read RTSP Port`\n" +
            "kill `pidof rtspd`",
            
            "# Modern command substitution syntax\n" +
            "port=$(/usr/sbin/userconfig -read RTSP Port)\n" +
            "kill $(pidof rtspd)"
        )
    
    # Build before/after examples from actual findings
    before_example = "# Command substitution with backticks\n" + "\n".join(examples)
    
    # Create corresponding after examples by replacing backticks with $()
    after_lines = []
    for line in examples:
        updated_line = line
        # Process all backtick expressions in this line
        pos = 0
        while '`' in updated_line[pos:]:
            start = updated_line.find('`', pos)
            end = updated_line.find('`', start + 1)
            if end == -1:  # No matching closing backtick
                break
                
            # Replace this backtick expression with $() syntax
            cmd_content = updated_line[start+1:end]
            updated_line = updated_line[:start] + "$(" + cmd_content + ")" + updated_line[end+1:]
            pos = start + len(cmd_content) + 3  # Position after the replacement
            
        after_lines.append(updated_line)
    
    after_example = "# Modern command substitution syntax\n" + "\n".join(after_lines)
    
    return (before_example, after_example)

def detect_code_context(file_path, finding_text):
    """Determine the code context (language, platform) from file path and finding."""
    if not file_path:
        return "general"
    
    # Get file extension and base name
    _, ext = os.path.splitext(file_path)
    file_name = os.path.basename(file_path)
    
    # Check for shell scripts based on extension or typical shell script patterns
    if ext in ['.sh', '.bash'] or file_name == 'sh' or '/bin/sh' in finding_text or '/bin/bash' in finding_text:
        return "bash"
    
    # Check for backtick command substitution typical in shell scripts
    if '`' in finding_text and ('$' in finding_text or '/' in finding_text):
        return "bash"
    
    # Check for C/C++ code
    if ext in ['.c', '.h', '.cpp', '.hpp', '.cc']:
        return "c"
    
    # Check for Python code
    if ext in ['.py', '.pyw']:
        return "python"
    
    # Check for PHP code
    if ext in ['.php', '.phtml']:
        return "php"
    
    # Check for common binary paths that likely contain C code
    if '/bin/' in file_path or '/sbin/' in file_path or '/lib/' in file_path:
        # For binary files, look for common C function calls in finding
        if any(func in finding_text for func in ['strcpy', 'sprintf', 'strcat', 'gets', 'system']):
            return "c"
    
    return "general"

def get_patch_recommendation(issue_type, finding_text, file_path=None, all_findings=None):
    """Get patch recommendation for a specific vulnerability type and content.
    
    Args:
        issue_type: Type of vulnerability
        finding_text: Text of the current finding
        file_path: Path to the file containing the vulnerability
        all_findings: List of all finding strings for this file/issue combination
    """
    if issue_type not in PATCH_RECOMMENDATIONS:
        return {
            "title": f"No specific recommendation for {issue_type}",
            "description": "Generic security best practices apply.",
            "recommendation": "Follow secure coding guidelines for your specific language and platform.",
            "references": ["https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/"]
        }
    
    # Determine the code context based on file path and finding content
    code_context = detect_code_context(file_path, finding_text)
    
    # Try to identify the specific vulnerability subtype from the finding text
    recommendations = PATCH_RECOMMENDATIONS[issue_type]
    best_match = None
    
    # Special handling for HARDCODED_CREDENTIAL
    if issue_type == "HARDCODED_CREDENTIAL":
        # Check if this is a key/certificate path
        if any(key_pattern in finding_text.lower() for key_pattern in ["key=", "cert=", ".pem", ".key", ".crt", "certificate"]):
            if "key" in recommendations:
                return recommendations["key"]
        
        # Check if this is in a config file
        config_extensions = ['.conf', '.cfg', '.ini', '.xml', '.json']
        if file_path and (any(file_path.endswith(ext) for ext in config_extensions) or 
                         '/etc/' in file_path or file_path.endswith('config')):
            if "config" in recommendations:
                return recommendations["config"]
    
    # Special handling for DANGEROUS_FUNCTION in binaries
    if issue_type == "DANGEROUS_FUNCTION" and all_findings and file_path:
        # Check if this is a binary file
        if '/bin/' in file_path or '/sbin/' in file_path or '/cgi-bin/' in file_path or file_path.endswith('.cgi'):
            # Generate recommendations for all dangerous functions found
            function_recommendations = get_binary_function_recommendations(all_findings)
            if function_recommendations:
                # Return the first recommendation (the rest will be added later)
                return function_recommendations[0]
    
    # If we have a specific context-based recommendation, use it first
    if code_context in recommendations:
        best_match = recommendations[code_context].copy()  # Make a copy we can modify
        
        # For bash scripts with command substitution, customize the examples
        if code_context == "bash" and all_findings and "`" in finding_text:
            before_example, after_example = generate_custom_bash_example(all_findings)
            best_match["before_patch"] = before_example
            best_match["after_patch"] = after_example
    else:
        # Find the best matching recommendation based on the finding text
        for key, recommendation in recommendations.items():
            if key != "general" and key in finding_text.lower():
                best_match = recommendation
                break
    
    # If no specific match found, use the general recommendation if available
    if best_match is None and "general" in recommendations:
        best_match = recommendations["general"]
    elif best_match is None and recommendations:
        # Just use the first recommendation as a fallback
        best_match = next(iter(recommendations.values()))
    
    return best_match if best_match else {
        "title": f"Generic recommendation for {issue_type}",
        "description": "This type of vulnerability requires careful remediation.",
        "recommendation": "Review the code and follow language-specific security best practices.",
        "references": ["https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/"]
    }

def recommend_patches(findings):
    """Generate patch recommendations for all findings."""
    recommendations = {}
    
    for issue_type, issues in findings.items():
        # Group findings by file path for more targeted recommendations
        files_with_issues = {}
        for issue in issues:
            file_path = issue.get("file_path", "")
            if file_path not in files_with_issues:
                files_with_issues[file_path] = []
            files_with_issues[file_path].append(issue)
        
        # Generate recommendations for each file with issues
        for file_path, file_issues in files_with_issues.items():
            # Collect all findings texts for this file/issue combination
            all_findings_text = "\n".join([issue.get("finding", "") for issue in file_issues])
            all_findings_list = [issue.get("finding", "") for issue in file_issues]
            
            # Special handling for dangerous functions in binaries - generate multiple recommendations
            if issue_type == "DANGEROUS_FUNCTION" and ('/bin/' in file_path or '/sbin/' in file_path or 
                                                   '/cgi-bin/' in file_path or file_path.endswith('.cgi')):
                
                function_recommendations = get_binary_function_recommendations(all_findings_list)
                
                # Create separate recommendation entries for each dangerous function
                for i, recommendation in enumerate(function_recommendations):
                    instance_key = f"{file_path}:{issue_type}:{i}"  # Add index to make keys unique
                    recommendations[instance_key] = {
                        "file_path": file_path,
                        "issue_type": issue_type,
                        "findings": all_findings_list,  # Include all findings for context
                        "recommendation": recommendation
                    }
                
                # Skip regular recommendation creation for this file
                continue
            
            # Regular recommendation creation for non-binary or non-dangerous-function cases
            recommendation = get_patch_recommendation(
                issue_type, 
                all_findings_text, 
                file_path, 
                all_findings_list
            )
            
            # Create a unique key for this specific instance
            instance_key = f"{file_path}:{issue_type}"
            if instance_key not in recommendations:
                recommendations[instance_key] = {
                    "file_path": file_path,
                    "issue_type": issue_type,
                    "findings": [],
                    "recommendation": recommendation
                }
            
            # Add individual findings to the recommendation
            for issue in file_issues:
                recommendations[instance_key]["findings"].append(issue.get("finding", ""))
    
    return recommendations


def print_patch_recommendations(recommendations):
    """Print patch recommendations in a formatted hierarchical way."""
    if not recommendations:
        print("\nNo recommendations available for the findings.")
        return
    
    print("\n" + "=" * 80)
    print(" VULNERABILITY REMEDIATION RECOMMENDATIONS ".center(80, "="))
    print("=" * 80)
    
    # Group recommendations by file path for better organization
    by_file_path = defaultdict(list)
    for rec in recommendations.values():
        by_file_path[rec["file_path"]].append(rec)
    
    # Print recommendations by file
    file_counter = 1
    for file_path, file_recs in by_file_path.items():
        print(f"\n{file_counter}. File: {file_path}")
        print("-" * 80)
        
        # Sort recommendations by title for consistency
        file_recs.sort(key=lambda x: x["recommendation"].get("title", ""))
        
        # Print each function recommendation for this file
        for i, rec in enumerate(file_recs, 1):
            recommendation = rec["recommendation"]
            print(f"\n  {chr(96+i)}. {recommendation['title']}")
            
            # IMPORTANT: Always print the actual findings - show ALL of them
            print("\n   Actual findings:")
            for finding in rec["findings"]:  # Show all findings without truncation
                print(f"    - {finding}")
            
            print(f"\n   Description: {recommendation['description']}")
            print(f"\n   Recommendation: {recommendation['recommendation']}")
            
            if "before_patch" in recommendation and "after_patch" in recommendation:
                print("\n   Example Patch:")
                print("    Before:")
                for line in recommendation["before_patch"].split("\n"):
                    print(f"      {line}")
                
                print("\n    After:")
                for line in recommendation["after_patch"].split("\n"):
                    print(f"      {line}")
            
            if "references" in recommendation:
                print("\n   References:")
                for ref in recommendation["references"]:
                    print(f"    - {ref}")
            
            if "real_world_examples" in recommendation:
                print("\n   Real-world Examples:")
                for example in recommendation["real_world_examples"]:
                    if "cve" in example:
                        print(f"    - {example['cve']}: {example['description']}")
                    else:
                        print(f"    - {example['project']}: {example['description']}")
        
        file_counter += 1
    
    print("\n" + "=" * 80)
    print(" END OF RECOMMENDATIONS ".center(80, "="))
    print("=" * 80)

def export_recommendations_to_html(recommendations, output_file):
    """Export patch recommendations to an HTML file with properly indented TOC."""
    try:
        # Create the directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        if not recommendations:
            with open(output_file, 'w') as f:
                f.write("<html><body class='dark-mode'><h1>No vulnerability remediation recommendations available</h1></body></html>")
            return True
        
        # Group recommendations by file path for better organization
        by_file_path = defaultdict(list)
        for rec in recommendations.values():
            by_file_path[rec["file_path"]].append(rec)
        
        # Start with a basic HTML template
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        /* Minimal dark theme matching screenshot */
        body { 
            font-family: Arial, sans-serif; 
            margin: 0;
            padding: 20px; 
            background-color: #0f1117; 
            color: #e5e7eb;
        }
        
        h1, h2, h3, h4 { 
            color: #3b82f6; 
        }
        
        a {
            color: #3b82f6;
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        .file-section { 
            margin-bottom: 30px; 
        }
        
        .function-section { 
            margin-bottom: 20px; 
            background-color: #1a1c25; 
            padding: 15px; 
            border-radius: 5px;
            border-left: 3px solid #3b82f6;
        }
        
        .example-code { 
            background-color: #111827; 
            padding: 10px; 
            border-radius: 5px; 
            font-family: monospace; 
            white-space: pre-wrap; 
        }
        
        .actual-findings { 
            background-color: #111827; 
            padding: 10px; 
            border-radius: 5px; 
            margin: 10px 0; 
        }
        
        /* Table of contents with proper indentation */
        .toc-area {
            margin-bottom: 40px;
        }
        
        .file-entry {
            margin-top: 10px;
            font-weight: bold;
            color: #3b82f6;
        }
        
        .vulnerability-entry {
            display: block;
            margin: 1px 0;
            color: #3b82f6;
            padding-left: 20px; /* Add indentation */
            font-weight: normal;
        }
        
        /* Recommendation area styles */
        .vulnerability-section {
            background-color: #1a1c25;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .vulnerability-header {
            margin-top: 0;
            margin-bottom: 20px;
        }
        
        .finding-details {
            margin-top: 15px;
        }
        
        .references {
            margin-top: 20px;
        }
        
        /* Code block styles */
        pre {
            background-color: #111827;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        /* Generic styles */
        .section-title {
            color: #3b82f6;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <h1>Vulnerability Report</h1>
"""
        
        # Add table of contents with proper indentation
        html += '<div class="toc-area">\n'
        
        file_counter = 1
        for file_path, file_recs in by_file_path.items():
            file_id = f"file-{file_counter}"
            # File entry with number
            html += f'<div class="file-entry">{file_counter}. File: {html_escape(os.path.basename(file_path))}</div>\n'
            
            # Sort recommendations by title for consistency
            file_recs.sort(key=lambda x: x["recommendation"].get("title", ""))
            
            # Add vulnerabilities with indentation
            for i, rec in enumerate(file_recs, 1):
                function_id = f"{file_id}-func-{i}"
                recommendation = rec["recommendation"]
                # Add indented vulnerability entry
                html += f'<a class="vulnerability-entry" href="#{function_id}">{chr(96+i)}. {html_escape(recommendation.get("title", "Recommendation"))}</a>\n'
            
            file_counter += 1
        
        html += '</div>\n'
        
        # Add recommendations by file
        file_counter = 1
        for file_path, file_recs in by_file_path.items():
            file_id = f"file-{file_counter}"
            html += f'<div class="file-section" id="{file_id}">\n'
            html += f'<h2>{file_counter}. File: {html_escape(file_path)}</h2>\n'
            
            # Sort recommendations by title for consistency
            file_recs.sort(key=lambda x: x["recommendation"].get("title", ""))
            
            # Add each function recommendation for this file
            for i, rec in enumerate(file_recs, 1):
                function_id = f"{file_id}-func-{i}"
                recommendation = rec["recommendation"]
                
                html += f'<div class="vulnerability-section" id="{function_id}">\n'
                html += f'<h3 class="vulnerability-header">{chr(96+i)}. {html_escape(recommendation.get("title", "Recommendation"))}</h3>\n'
                
                # ALWAYS add the actual findings - show ALL of them
                html += '<div class="actual-findings">\n'
                html += '<strong>Actual findings:</strong>\n'
                html += '<ul>\n'
                for finding in rec["findings"]:  # Show all findings without truncation
                    html += f'<li>{html_escape(finding)}</li>\n'
                html += '</ul>\n'
                html += '</div>\n'
                
                # Add description and recommendation
                if "description" in recommendation:
                    html += f'<div class="finding-details"><strong>Description:</strong> {html_escape(recommendation["description"])}</div>\n'
                
                if "recommendation" in recommendation:
                    html += f'<div class="finding-details"><strong>Recommendation:</strong> {html_escape(recommendation["recommendation"])}</div>\n'
                
                # Add example patch if available
                if "before_patch" in recommendation and "after_patch" in recommendation:
                    html += '<div class="before-after">\n'
                    
                    html += '<h4 class="section-title">Before:</h4>\n'
                    html += f'<pre>{html_escape(recommendation["before_patch"])}</pre>\n'
                    
                    html += '<h4 class="section-title">After:</h4>\n'
                    html += f'<pre>{html_escape(recommendation["after_patch"])}</pre>\n'
                    
                    html += '</div>\n'
                
                # Add references
                if "references" in recommendation and recommendation["references"]:
                    html += '<div class="references">\n'
                    html += '<strong>References:</strong>\n'
                    html += '<ul>\n'
                    for ref in recommendation["references"]:
                        if ref and ref.startswith('http'):
                            html += f'<li><a href="{html_escape(ref)}" target="_blank">{html_escape(ref)}</a></li>\n'
                        elif ref:  # Only add non-empty references
                            html += f'<li>{html_escape(ref)}</li>\n'
                    html += '</ul>\n'
                    html += '</div>\n'
                
                # Add real-world examples
                if "real_world_examples" in recommendation and recommendation["real_world_examples"]:
                    html += '<div class="real-world">\n'
                    html += '<strong>Real-world Examples:</strong>\n'
                    html += '<ul>\n'
                    for example in recommendation["real_world_examples"]:
                        if example and "cve" in example and "description" in example:
                            html += f'<li>{html_escape(example["cve"])}: {html_escape(example["description"])}</li>\n'
                        elif example and "project" in example and "description" in example:
                            html += f'<li>{html_escape(example["project"])}: {html_escape(example["description"])}</li>\n'
                    html += '</ul>\n'
                    html += '</div>\n'
                
                html += '</div>\n'  # Close vulnerability-section div
            
            html += '</div>\n'  # Close file-section div
            file_counter += 1
        
        # Close the HTML document
        html += """
</body>
</html>
"""
        
        # Write to file all at once
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"\nRemediation recommendations exported to {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting recommendations to HTML: {str(e)}")
        return False


def html_escape(text):
    """Escape HTML special characters in text."""
    if text is None:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

# Main function for testing the module independently
def main():
    # Example findings
    example_findings = {
        "DANGEROUS_FUNCTION": [
            {
                "file_path": "/bin/firmware_app",
                "finding": "Potentially dangerous function 'strcpy' found at address 0x12345678",
                "severity": "MEDIUM"
            },
            {
                "file_path": "/bin/network_service",
                "finding": "Potentially dangerous function 'sprintf' found at address 0x87654321",
                "severity": "MEDIUM"
            }
        ],
        "HARDCODED_CREDENTIAL": [
            {
                "file_path": "/etc/config.ini",
                "finding": "password=admin123",
                "severity": "HIGH",
                "line_num": 42
            }
        ]
    }
    
    # Generate recommendations
    recommendations = recommend_patches(example_findings)
    
    # Print recommendations
    print_patch_recommendations(recommendations)
    
    # Export to HTML
    export_recommendations_to_html(recommendations, "vulnerability_recommendations.html")

if __name__ == "__main__":
    main()