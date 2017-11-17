blacklist-scripts
=================
This is a collection of shell scripts that are intended to block Linux systems and OpenWRT routers from known sources of malicious traffic. These scripts use `iptables` with highly efficient `ipset` module to check incoming traffic against blacklists populated from publicly available sources.

[Emerging Threats](http://rules.emergingthreats.net/fwrules/) provides similar rules that essentially run `iptables` for *each* blacklisted IP which is extremely inefficient in case of large blacklists. Using `ipset` means using just one `iptables` rule to perform a very efficient lookup in hash structure created by `ipset`.


**Note:** This script is a quick hack suitable primarily for embedded devices (OpenWRT, LEDE) rather than a complete solution for server. For the latter, have a look at [FireHOL](http://firehol.org/) and its excellent [FireHOL IP Lists](http://iplists.firehol.org/) add-on. Have a look at the **FireHOL** section further down.

## Available blacklists
If you decide to use this script, these are the blacklists available by default:

* [Emerging Threats](http://rules.emergingthreats.net/fwrules/) - list of other known threats (botnet C&C, compromised servers etc) compiled from various sources, including [Spamhaus DROP](http://www.spamhaus.org/drop/), [Shadoserver](https://www.shadowserver.org/wiki/) and [DShield Top Attackers](http://www.dshield.org/top10.html)
* [www.blocklist.de](https://www.blocklist.de/en/index.html) - list of known password bruteforcers supplied by a network of [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) users
* [iBlocklist](https://www.iblocklist.com/lists.php) - various free and subscription based lists
* [Bogons](http://www.team-cymru.org/Services/Bogons/) - IP subnets that should never appear on public Internet; this includes [RFC 1918](http://tools.ietf.org/html/rfc1918) networks so running this on a machine in a private network will effectively **shut its networking down**

By default the script will only load Emerging Threats and Blocklist.de collections. Others may be added by simply appending to the `URLS` variable in the beginning of the script:

    URLS="http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    URLS="$URLS https://www.blocklist.de/downloads/export-ips_all.txt"

The script ignores empty lines or comments and will only extract anything that looks like an IP address (`a.b.c.d`) or CIDR subnet (`a.b.c.d/nn`). Each blacklist is loaded into a separate `ipset` collection so that logging unambigously identifies which blacklist blocked a packet.

The script also creates an empty `manual-blacklist` set that can be used by the administrator for manual blacklisting. For example:

    ipset add manual-blacklist 217.146.93.122

Removal:

    ipset delete manual-blacklist 217.146.93.122

## OpenWRT
The script automatically detects OpenWRT environment (looking for `uci`) and will try to obtain the WAN interface name. The filtering will be then **limited to WAN interface only.**

Requirements:

* `opkg install ipset curl`

Installation:

    cp blacklist.sh /etc/firewall.user
    echo "01 01 * * * sh /etc/firewall.user" >>/etc/crontabs/root

The blacklist will be updated on daily basis.

Manual run:

    sh /etc/firewall.user
    
### LEDE
On LEDE the firewall comes up **before** network interfaces are configured so a service file is required to bring the blacklist when network is available. Create `/etc/init.d/blacklist` with the following contents and `chmod a+x /etc/init.d/blacklist`:
````
#!/bin/sh /etc/rc.common
START=30
COMMAND="sh /etc/firewall.user"
boot() {
   $COMMAND
}
````

## Linux
Requirements:

* On Debian, Ubuntu and other `apt` systems: `apt-get install ipset curl`
* On RedHat, Fedora, CentOS and other RPM systems: `yum install ipset curl`

Installation:

    cp blacklist.sh /etc/cron.daily/blacklist

The blacklist will be updated on daily basis.

Manual run:

    sh /etc/cron.daily/blacklist

# Integration with OSSEC
[OSSEC HIDS](http://www.ossec.net/) is a host-intrusion detection engine for Unix and Windows servers. Its [active response](http://ossec-docs.readthedocs.org/en/latest/manual/ar/index.html) feature allows running a script in response to configured events, for example blocking an IP address detected as attempting to continuously bruteforce a SSH password.

The `ipset-drop.sh` is active response script to add offending IP addresses to a `manual-blacklist` set also created by the `blacklist.sh` script.

Installation:

    cp ipset-drop.sh /var/ossec/active-response/bin

Example OSSEC configuration:

    <command>
      <name>ipset-drop</name>
      <executable>ipset-drop.sh</executable>
      <expect>srcip</expect>
      <timeout_allowed>yes</timeout_allowed>
    </command>

    <active-response>
      <command>ipset-drop</command>
      <location>local</location>
      <rules_id>5720</rules_id> <!-- Rule: 5720 fired (level 10) -> Multiple SSHD authentication failures. -->
    </active-response>

Another script `router-drop.sh` will perform the same action on a remote router over SSH. This is useful in case of embedded routers where OSSEC agent installation is unfeasibile. OpenWRT logs (over syslog) to a more powerful Linux box with OSSEC installed. On alerts the active response script installed that blocks uoffending IP addresses on the router:

```
  +---------+ ----- syslog -------> +-------+
--| OpenWRT |                       | Linux |
  |         |                       | OSSEC |
  +---------+ <- active response -- +-------+

```

The `router-drop.sh` script requires two configuration steps:

* configure the `ROUTER` variable to a SSH string for root login to the router (e.g. *root@gw.example.com*)
* install SSH keys to actually log in; the keys need to be installed on root account as this is where active response script are running

Example configuration:

     <command>
       <name>router-drop</name>
       <executable>router-drop.sh</executable>
       <expect>srcip</expect>
       <timeout_allowed>no</timeout_allowed>
     </command>
   
     <active-response>
       <command>router-drop</command>
       <location>local</location>
       <rules_id>51004</rules_id>
     </active-response>

Event 51004 is defined in `/var/ossec/rules/dropbear_rules.xml` and triggered by a series of unsuccessful password logins. Don't forget to add your trusted networks to `<white_list>` entries to prevent locking yourself out!

## Samples

Number of blacklisted IP addresses:

    # ipset list | wc -l
    26160

Traffic (ICMP and TCP) from blacklisted IP addresses in router logs (OpenWRT):

    # dmesg|grep BLOCK
    [745433.590000] BLOCK emerging-Block-IPs.txt IN=eth0.2 OUT=br-lan MAC=64:70:12:c2:64:70:02:cc:24:73:9c:97:26:50:b9:10:08:00 SRC=217.146.93.122 DST=10.10.10.20 LEN=28 TOS=0x00 PREC=0x00 TTL=56 ID=54090 PROTO=ICMP TYPE=0 CODE=0 ID=48891 SEQ=0 MARK=0x10 
    [745433.620000] BLOCK emerging-Block-IPs.txt IN=eth0.2 OUT=br-lan MAC=64:70:12:c2:64:70:02:cc:24:73:9c:97:26:50:b9:10:08:00 SRC=144.76.71.210 DST=10.10.10.20 LEN=28 TOS=0x00 PREC=0x40 TTL=51 ID=17805 PROTO=ICMP TYPE=0 CODE=0 ID=28814 SEQ=0 MARK=0x10 
    [745484.510000] BLOCK emerging-Block-IPs.txt IN=eth0.2 OUT=br-lan MAC=64:70:12:c2:64:70:02:cc:24:73:9c:97:26:50:b9:10:08:00 SRC=69.194.235.103 DST=10.10.10.20 LEN=44 TOS=0x00 PREC=0x00 TTL=45 ID=0 DF PROTO=TCP SPT=443 DPT=58827 WINDOW=5840 RES=0x00 ACK SYN URGP=0 MARK=0x33

Traffic (SSH bruteforce scanners) from blacklisted IP addresses in web server logs (CentOS):

    BLOCK export-ips_all.txt IN=eth1 OUT= MAC=bc:16:2e:08:69:d4:3c:08:f6:d9:93:a5:08:00 SRC=122.225.97.79 DST=10.179.134.230 LEN=40 TOS=0x00 PREC=0x00 TTL=101 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0 
    BLOCK export-ips_all.txt IN=eth1 OUT= MAC=bc:16:2e:08:69:d4:3c:08:f6:d9:93:a5:08:00 SRC=61.174.51.207 DST=10.179.134.230 LEN=40 TOS=0x00 PREC=0x00 TTL=102 ID=256 PROTO=TCP SPT=6000 DPT=22 WINDOW=16384 RES=0x00 SYN URGP=0

Traffic (SSH password bruteforce scanners) blocked by [OSSEC HIDS](http://www.ossec.net/) (Linux):

    BLOCK manual-blacklist IN=eth1 OUT= MAC=bc:76:2e:08:69:d4:3c:08:f6:d9:93:a5:08:00 SRC=89.46.14.48 DST=10.179.134.230 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=62214 DF PROTO=TCP SPT=51436 DPT=22 WINDOW=5840 RES=0x00 SYN URGP=0 
    BLOCK manual-blacklist IN=eth1 OUT= MAC=bc:76:2e:08:69:d4:3c:08:f6:d9:93:a5:08:00 SRC=89.46.14.48 DST=10.179.134.230 LEN=60 TOS=0x00 PREC=0x00 TTL=48 ID=62215 DF PROTO=TCP SPT=51436 DPT=22 WINDOW=5840 RES=0x00 SYN URGP=0 

## FireHOL Blacklists
If you are looking for a mature firewall management solution for Linux that supports blacklists, definitely have a look at [FireHOL](http://firehol.org/) and its excellent [FireHOL IP Lists](http://iplists.firehol.org/) add-on. Compared to FireHOL, this script is a quick hack and I keep maintaining it primarily because FireHOL seems to be an overkill for OpenWRT/LEDE devices.

Quick start with FireHOL blacklists:

* Run `update-ipsets enable dshield` and then `update-ipsets`
* Modify `/etc/firehol/firehol.conf` (remember to run `firehol start` afterwards)

```
ipv4 ipset create dshield hash:net
ipv4 ipset addfile dshield ipsets/dshield.netset
blacklist4 stateful inface eth0 connlog "BLACKLIST " ipset:dshield
interface eth0 world4
    server4 ssh deny src4 ipset:manual-blacklist
    ...
```
