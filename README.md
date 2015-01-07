blacklist-scripts
=================
This is a collection of shell scripts that are intended to block Linux systems and OpenWRT routers from known sources of malicious traffic. These scripts use `iptables` with highly efficient `ipset` module to check incoming traffic against blacklists populated from publicly available sources.

[Emerging Threats](http://rules.emergingthreats.net/fwrules/) provides similar rules that essentially run `iptables` for *each* blacklisted IP which is extremely inefficient in case of large blacklists. Using `ipset` means using just one `iptables` rule to perform a very efficient lookup in hash structure created by `ipset`.

## Block lists

* [Emerging Threats](http://rules.emergingthreats.net/fwrules/) - list of other known threats (botnet C&C, compromised servers etc) compiled from various sources, including [Spamhaus DROP](http://www.spamhaus.org/drop/), [Shadoserver](https://www.shadowserver.org/wiki/) and [DShield Top Attackers](http://www.dshield.org/top10.html)
* [www.blocklist.de](https://www.blocklist.de/en/index.html) - list of known password bruteforcers supplied by a network of [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) users
* [iBlocklist](https://www.iblocklist.com/lists.php) - various free and subscription based lists
* [Bogons](http://www.team-cymru.org/Services/Bogons/) - IP subnets that should never appear on public Internet; this includes RFC 1918 networks, **be careful with deploying this in private networks**

By default the script will only load Emerging Threats and Blocklist.de collections. Others may be added by simply appending to the `urls` variable in the beginning of the script:

    urls="http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    urls="$urls https://www.blocklist.de/downloads/export-ips_all.txt"

The script ignores empty lines or comments and will only extract anything that looks like an IP address (`a.b.c.d`) or CIDR subnet (`a.b.c.d/nn`). Each blacklist is loaded into a separate `ipset` collection so that logging unambigously identifies which blacklist blocked a packet.

## OpenWRT
The script automatically detects OpenWRT environment (looking for `uci`) and will try to obtain the WAN interface name. The filtering will be then **limited to WAN interface only.**

Requirements:

* `opkg install ipset curl`

Installation:

    cp blacklist.sh /etc/firewall.user
    echo "01 01 * * * sh /etc/firewall.user" >>/etc/crontabs/root

Manual run:

    sh /etc/firewall.user

## Linux
Requirements:

* On Debian, Ubuntu and other `apt` systems: `apt-get install ipset curl`
* On RedHat, Fedora, CentOS and other RPM systems: `yum install ipset curl`

Installation:

    cp blacklist.sh /etc/cron.daily/blacklist

Manual run:

    sh /etc/cron.daily/blacklist

