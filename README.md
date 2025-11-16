# Help aur version
python3 reconx.py -h
python3 reconx.py -version

# Intel gathering
python3 reconx.py intel -d facebook.com
python3 reconx.py intel -d google.com -active

# Enumeration
python3 reconx.py enum -d facebook.com
python3 reconx.py enum -d facebook.com -ports -txt results.txt
python3 reconx.py enum -d facebook.com -active -ports -o results.json
