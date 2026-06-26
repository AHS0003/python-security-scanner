"""
sample_vulnerable.py – Fichier de test pour l'agent SAST
Contient intentionnellement des vulnérabilités.
"""

import os
import subprocess

# Secrets hardcodés (CRITICAL)
password = "super_secret_password"
api_key  = "123456789abcdef"

# Injection de code (HIGH)
user_input = input("Enter expression: ")
eval(user_input)

code_block = input("Enter code: ")
exec(code_block)

# Exécution système (HIGH)
os.system("ls -la")

# Subprocess (MEDIUM)
subprocess.run(["echo", "hello"])
subprocess.call("rm -rf /tmp/test", shell=True)