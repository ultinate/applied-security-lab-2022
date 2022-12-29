# Accept all traffic during the provisioning phase
echo "Accept all"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Remove all existing rules
echo "Remove all existing"
iptables -F

##### BEGIN: INCOMING #####

# HTTPS (nginx)
echo "INCOMING HTTPS"
iptables -A INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# HTTP/S (Flask)
echo "INCOMING HTTP/S (lo)"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# SSH
echo "INCOMING SSH"
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

##### END: INCOMING #####


##### BEGIN: OUTGOING #####

# HTTPS (pip)
echo "OUTGOING HTTPS"
iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# DNS (pip)
echo "OUTGOING DNS"
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 5353 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 5353 -m state --state NEW,ESTABLISHED -j ACCEPT

# syslog
echo "OUTGOING SYSLOG"
iptables -A INPUT -p tcp --sport 2100 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 2100 -m state --state NEW,ESTABLISHED -j ACCEPT

##### END: OUTGOING #####

# Explicit drop rule for pings to be able to track suspicius activity in the network with "iptables -tfilter -vnxL"
iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW,ESTABLISHED -j DROP

# Set default chain policies for actual security
echo "SET DEFAULTS"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

sudo ip6tables -F
echo "SET IPv6"
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP


echo "DONE SET DEFAULTS"
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6
echo "PERSISTED RULES"
