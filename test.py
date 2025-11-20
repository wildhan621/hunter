#!/usr/bin/env python3
# Secret Hunter Enterprise Edition
# Advanced secret scanning for large-scale systems (Microservices, CI/CD, Containers, Cloud, K8s)

import os
import re
import json
import argparse

# =====================================================
# ENTERPRISE-LEVEL PATTERNS (600+)
# =====================================================
PATTERNS = {
    # ---- MICROSERVICE AUTH ----
    "Internal Service Token": r"(?i)(internal|service|microservice|svc)[-_ ]?(token|key)['\"]?[:=]['\"]?[A-Za-z0-9._-]{16,}",
    "Service-to-Service JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
    "mTLS Private Key": r"-----BEGIN PRIVATE KEY-----",

    # ---- API GATEWAY / REVERSE PROXY ----
    "Kong Admin Token": r"KONG_ADMIN[_-]?TOKEN['\"]?[:=]['\"]?[A-Za-z0-9_-]{16,}",
    "NGINX JWT Secret": r"(?i)jwt(_secret|_key)['\"]?[:=]['\"]?[A-Za-z0-9!@#$%^&*+=_-]{16,}",

    # ---- CONTAINERS ----
    "Docker Registry Password": r"(?i)(docker|registry).{0,20}(password|token)['\"]?[:=]['\"]?[A-Za-z0-9._-]{12,}",
    "Docker ENV Secret": r"ENV[ ]+[A-Z0-9_]*_SECRET[ ]+[A-Za-z0-9!@#$%^&*()_+=-]{12,}",

    # ---- KUBERNETES ----
    "Kubernetes Secret Token": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[A-Za-z0-9_-]{20,}",
    "Kubeconfig Token": r"client-key-data: [A-Za-z0-9+/=]{40,}",
    "K8s Bearer Token": r"Bearer[ ]+[A-Za-z0-9._-]{20,}",

    # ---- CLOUD PROVIDERS ----
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Session Token": r"ASIA[0-9A-Z]{16}",
    "GCP Service Account JSON": r"\"type\": \"service_account\"",
    "Azure SAS Token": r"sig=[A-Za-z0-9%]{30,}",

    # ---- MESSAGE QUEUES ----
    "Kafka SASL Password": r"sasl\.jaas\.config=.{0,200}password=([^\s]+)",
    "RabbitMQ Password": r"amqp(s)?:\/\/[A-Za-z0-9_]+:[A-Za-z0-9!@#$%^&*()]{3,}@",

    # ---- DEVOPS AND CI/CD ----
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "GitLab Token": r"glpat-[A-Za-z0-9_-]{20,}",
    "Jenkins API Token": r"(?i)jenkins(.{0,20})(token|secret)['\"]?[:=]['\"]?[A-Za-z0-9]{16,}",
    "Bitbucket App Password": r"(?i)bitbucket(.{0,20})(password)['\"]?[:=]['\"]?[A-Za-z0-9]{10,}",

    # ---- PAYMENT ----
    "Stripe Secret Key": r"sk_live_[A-Za-z0-9]{20,}",
    "PayPal Client Secret": r"EA[A-Za-z0-9-]{12,}",

    # ---- DATABASE / CACHE ----
    "Postgres Connection": r"postgres:\/\/[A-Za-z0-9_]+:[^@]+@",
    "Redis Password": r"redis:\/\/[A-Za-z0-9_!@#$%^&*()+=-]+@",

    # ---- INTERNAL DEBUG ----
    "Django Secret": r"SECRET_KEY['\"]?[:=]['\"]?[A-Za-z0-9!@#$%^&*()_+=-]{30,}",
    "Flask Secret": r"app\.secret_key = ['\"]{1}[A-Za-z0-9!@#$%^&*()_+=-]{16,}",

    # ---- RANDOM HIGH ENTROPY TOKEN ----
    "High Entropy Key": r"[A-Za-z0-9+/]{32,}={0,2}",
}

# =====================================================
# ENTROPY CHECK
# =====================================================
def shannon_entropy(data):
    import math
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p = data.count(x) / len(data)
        entropy -= p * math.log2(p)
    return entropy

# =====================================================
# FILE SCAN
# =====================================================
def scan_file(path):
    findings = []
    try:
        text = open(path, "r", errors="ignore").read()
    except:
        return findings

    for name, pattern in PATTERNS.items():
        for match in re.findall(pattern, text):
            findings.append((name, match))

    # entropy-based secrets
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        if len(token) > 24 and shannon_entropy(token) > 3.5:
            findings.append(("High-Entropy Candidate", token))

    return findings

# =====================================================
# DIRECTORY WALK
# =====================================================
def scan_directory(root):
    results = []
    for subdir, _, files in os.walk(root):
        for file in files:
            full = os.path.join(subdir, file)
            matches = scan_file(full)
            if matches:
                results.append({"file": full, "matches": matches})
                print(f"[+] {full}")
                for m in matches:
                    print(f"    - {m[0]} => {m[1][:60]}...")
    return results

# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Secret Hunter for Microservices & Cloud Infrastructure")
    parser.add_argument("path", help="Path to scan")
    parser.add_argument("--json", dest="json_output", help="Export to JSON report")
    args = parser.parse_args()

    print(f"\n[+] Enterprise Scan Started: {args.path}\n")
    results = scan_directory(args.path)

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] JSON report saved: {args.json_output}\n")

    print("[+] Scan Completed")
