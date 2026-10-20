# ssh-logwatch

Lit un fichier auth.log et repère les adresses IP qui tentent du brute-force
SSH (beaucoup d'échecs de mot de passe). Pratique pour comprendre ce que fait
un fail2ban en version bien plus simple.

## Utilisation

```
python logwatch.py                 # utilise sample_auth.log fourni
python logwatch.py /var/log/auth.log
```

Le seuil de détection est dans le fichier (`SEUIL = 5`).

Un `sample_auth.log` est fourni pour tester sans avoir besoin d'un vrai log,
il contient une IP clairement en train de brute-forcer.

## Idées pour plus tard

- fenêtre de temps (X échecs en Y minutes, pas juste un total)
- sortir une liste d'IP prête à passer dans iptables
- gérer aussi les logs au format journald / syslog différents
