# NULL Scan

sudo nmap -sN 172.22.0.1 -p 8080,9090,8000,3000,5432,5678

# XMAS Scan

sudo nmap -sX 10.3.46.58 -p 8080,9090,8000,3000,5432,5678

# FIN Scan

sudo nmap -sF 10.3.46.58 -p 8080,9090,8000,3000,5432,5678

# OS Fingerprinting

sudo nmap -O 172.20.10.3 -p 8080,9090,8000,3000,5432,5678

