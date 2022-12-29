# Accept all traffic during the provisioning phase
echo "Accept all"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Remove all existing rules
iptables -F

##### BEGIN: INCOMING #####

# SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

##### END: INCOMING #####


##### BEGIN: OUTGOING #####

# DNS (pip)
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 5353 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --dport 5353 -m state --state NEW,ESTABLISHED -j ACCEPT

# syslog
iptables -A INPUT -p tcp --dport 2100 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 2100 -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH
iptables -A INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

##### END: OUTGOING #####

# Explicit drop rule for pings to be able to track suspicius activity in the network with "iptables -tfilter -vnxL"
iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW,ESTABLISHED -j DROP


# Set default chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

sudo ip6tables -F
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP


echo "DONE SET DEFAULTS"
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6
echo "PERSISTED RULES"
