# Accept all traffic during the provisioning phase
echo "Accept all"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Remove all existing rules
echo "Remove all existing"
iptables -F

##### BEGIN: INCOMING #####


echo "INCOMING HTTPS"
# HTTPS (nginx)
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

echo "INCOMING LOCAL"
# HTTP/S (Flask)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "INCOMING SSH"
# SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT


##### END: INCOMING #####


##### BEGIN: OUTGOING #####

echo "OUTGOING SYSLOG"
# syslog
iptables -A INPUT -p tcp --sport 2100 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 2100 -m state --state NEW,ESTABLISHED -j ACCEPT

echo "OUTGOING HTTPS"
# HTTP/S (pip, flask)
iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

echo "OUTGOING DNS"
# DNS (pip)
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 5353 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 5353 -m state --state NEW,ESTABLISHED -j ACCEPT


##### END: OUTGOING #####

# Explicit drop rule for pings to be able to track suspicius activity in the network with "iptables -tfilter -vnxL"
iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW,ESTABLISHED -j DROP

##### END: OUTGOING #####

echo "SET DEFAULTS"
# Set default chain policies for actual security
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

echo "SET IPv6"
sudo ip6tables -F
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP


echo "DONE SET DEFAULTS"
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6
echo "PERSISTED RULES"
