# iptables-nload

This script is designed to display and analyze traffic based on iptables rules.
```
Options:
        -c|--chain <CHAIN>              iptables chain to watch (mandatory).
        -t|--table <TABLE>              the table CHAIN belongs to.
                                        default is 'filter'
        -i|--interval <INTERVAL>        the refresh interval of the display in milliseconds.
                                        default is 100
        -p|--period <PERIOD>            the period of calculation statistics in seconds.
                                        default is 60
        -d|--direction <in|out>         Direction of traffic to sort by.
                                        default is 'in'
        --total <PREFIX>                Prefix of values to calculate min/max by. If not specified, min/max will be alculated for each value separately.
        -u|--unit k|m|g                 Type of unit used for the display of traffic numbers.
        --packets                       Show pps. It isn't shown by default.
        -h|--help                       Print this help and exit.
```

1. Send all traffic, which you want to analyze, to specified chain. E.g.:
```bash
iptables -N IPTABLES_NLOAD
iptables -I INPUT -j IPTABLES_NLOAD
iptables -I OUTPUT -j IPTABLES_NLOAD
```

2. Fill specified chain with no-effect rules (without -j or -j RETURN). All rules must use module *comment*, which must be set with the following pattern: *key_direction*. The direction is must be one of *in* or *out*. E.g.:
```bash
iptables -A IPTABLES_NLOAD -i eth0 -m comment --comment "total_in"
iptables -A IPTABLES_NLOAD -o eth0 -m comment --comment "total_out"
iptables -A IPTABLES_NLOAD -o eth0 -p tcp -m tcp --sport 22 -m comment --comment "ssh_out" -j RETURN
iptables -A IPTABLES_NLOAD -i eth0 -p tcp -m tcp --dport 22 -m comment --comment "ssh_in" -j RETURN
iptables -A IPTABLES_NLOAD -i eth0 -m comment --comment "other_in" -j RETURN
iptables -A IPTABLES_NLOAD -o eth0 -m comment --comment "other_out" -j RETURN
```

3. Run the script as described in usage above. E.g.: the command below will start displaying and analyzing traffic passing chain IPTABLES_NLOAD, sorted by outgoing traffic with renewal interval 200 msec and statistics calculated for 5 mins. Max traffic will be calculated based on lines with key *total*: all values in *max* columns will be taken at the moment, when *total* line will have reached its maximum value.
```bash
./iptables_nload.pl --chain=IPTABLES_NLOAD --interval=200 --period=300 --direction=out --total=total --unit=m
```

4. Press H while script is working to display help on shortcuts you can use:
```
Supported hotkeys:
	H - show / hide this help
	F - flush stats
	S - start / stop updating stats
	U - change displayed units (b/Kb/Mb/Gb)
	I - sort by incoming traffic
	O - sort by outgoing traffic
	1..5 - number of the field to sort by
	B - show / hide bps
	P - show / hide pps
	Q - quit
```

P.S. You can use iptables-restore located in this directory for demo usage:

```bash
iptables-restore -n < iptables.example
```
