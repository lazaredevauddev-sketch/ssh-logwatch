#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

# On parse /var/log/auth.log et on repère les IP qui accumulent
# des echecs de connexion ssh. Au dela d'un seuil -> suspect.

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
SEUIL = 5


def parse(path):
    attempts = defaultdict(list)   # ip -> [user, user, ...]
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                attempts[ip].append(user)
    return attempts


def report(attempts):
    suspects = {ip: users for ip, users in attempts.items() if len(users) >= SEUIL}
    if not suspects:
        print("rien d'anormal")
        return

    print(f"{len(suspects)} IP suspectes (>= {SEUIL} echecs)\n")
    for ip, users in sorted(suspects.items(), key=lambda x: len(x[1]), reverse=True):
        uniq = set(users)
        print(f"{ip} : {len(users)} echecs sur {len(uniq)} comptes")
        print(f"    comptes vises: {', '.join(sorted(uniq)[:10])}")


if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    report(parse(log))
