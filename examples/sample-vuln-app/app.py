"""Deliberately vulnerable sample app for VulnForge demos. DO NOT deploy.

Contains: SQL injection, command injection, a hardcoded secret, and weak crypto -
so SAST has something real to find when you run:

    vulnforge scan --path examples/sample-vuln-app --description examples/app-description.yaml --out runs/sample
"""
import hashlib
import os
import sqlite3
import subprocess

# Hardcoded secret (Gitleaks / Semgrep should flag this).
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_TOKEN = "tok_live_51H8xYzAbCdEfGhIjKlMnOpQrSt"


def get_order(order_id):
    conn = sqlite3.connect("orders.db")
    cur = conn.cursor()
    # SQL injection: user input concatenated into the query.
    cur.execute("SELECT * FROM orders WHERE id = '%s'" % order_id)
    return cur.fetchall()


def ping(host):
    # Command injection: untrusted input into a shell.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def hash_password(password):
    # Weak hashing for passwords.
    return hashlib.md5(password.encode()).hexdigest()
