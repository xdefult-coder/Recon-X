# Help aur version
python3 reconx.py -h
python3 reconx.py -version

# Intel gathering
python3 reconx.py intel -d example.com
python3 reconx.py intel -d example -active

# Enumeration
python3 reconx.py enum -d example.com
python3 reconx.py enum -d example.com -ports -txt results.txt
python3 reconx.py enum -d example.com -active -ports -o results.json

# Script ko executable banao
chmod +x reconx.py

# Alias banao (optional)
alias reconx='python3 /root/Desktop/Recon-X/reconx.py'

# Phir direct use karo
reconx intel -d example.com
