#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long qw(GetOptions);
use Time::HiRes qw(usleep);
use List::Util qw(min max sum);
use Term::ReadKey;
use POSIX;
use File::Basename;
use Data::Dumper;

my $opt = {
	chain		=> undef,
	table		=> q(filter),
	interval	=> 100,
	period		=> 60,
	direction	=> q(in),
	total		=> undef,
	unit		=> q(k),
	help		=> q(),
	bytes	=> 1,
	packets	=> q(),
};
my @sort_fields = qw(cur avg min max cur_avg max_avg);
my @units = ( q( ), qw(K M G));
my $h = 1;

sub get_max {
	my (@data) = @_;
	my $i = $#data;
	my $max = $i;
	$max = $data[$i] > $data[$max] ? $i : $max while $i--;
	return $max;
}

sub get_min {
	my (@data) = @_;
	my $i = $#data;
	my $min = $i;
	$min = $data[$i] < $data[$min] ? $i : $min while $i--;
	return $min;
}

sub print_usage {
	my ($message) = @_;
	my $name = basename($0);
	my $usage = <<EOF
Usage: $name [options]

Options:
\t-c|--chain <CHAIN>\t\tiptables chain to watch (mandatory).
\t-t|--table <TABLE>\t\tthe table CHAIN belongs to.
\t\t\t\t\tdefault is 'filter'
\t-i|--interval <INTERVAL>\tthe refresh interval of the display in milliseconds.
\t\t\t\t\tdefault is 100
\t-p|--period <PERIOD>\t\tthe period of calculation statistics in seconds.
\t\t\t\t\tdefault is 60
\t-d|--direction <in|out>\t\tDirection of traffic to sort by.
\t\t\t\t\tdefault is 'in'
\t--total <PREFIX>\t\tPrefix of values to calculate min/max by. If not specified, min/max will be calculated for each value separately.
\t-u|--unit k|m|g\t\t\tType of unit used for the display of traffic numbers.
\t--packets\t\t\tShow pps. It isn't shown by default.
\t-h|--help\t\t\tPrint this help and exit.
EOF
;
	if ($message) {
		print (STDERR qq(\033[31;1m$message\033[0m\n\n));
		print (STDERR $usage);
		exit 1;
	} else {
		print $usage;
		exit 0;
	}
}

sub print_hotkeys {
	my $help = <<EOF
\033[1J
\033[1;1H
Supported hotkeys:
	H - show / hide this help
	F - flush stats
	S - start / stop updating stats
	U - change displayed units (b/Kb/Mb/Gb)
	I - sort by incoming traffic
	O - sort by outgoing traffic
	1..$#sort_fields - number of the field to sort by
	B - show / hide bps
	P - show / hide pps
	Q - quit
EOF
;
	print $help;
}

sub check_options {
	my ($opt) = @_;
	print_usage() if $opt->{help};
	my @tables = qw(nat raw filter mangle);
	my @directions = qw(in out);
	my %units_hash = map { $units[$_] => $_ } 0..$#units;
	print_usage(q(Specify --chain!)) unless defined $opt->{chain};
	print_usage(q(Table must be one of ).join('/',@tables).q(!)) if (! ($opt->{table} ~~ @tables));
	print_usage(q(There is no such table/chain combination!)) if system(qq(iptables -t $opt->{table} -S $opt->{chain} > /dev/null));
	print_usage(q(Unit must be one of ).join('/',@units).q(!)) if (! (uc($opt->{unit}) ~~ @units));
	$h = int($units_hash{uc($opt->{unit})});
	print_usage(q(Direction (-d) must be 'in' or 'out'!)) if (! ($opt->{direction} ~~ @directions));	
}

sub nload {
	my $res;
	my $i = 0;
	my $stop = 0;
	my $help = 0;
	my $period = int($opt->{period}*1000/$opt->{interval});
	my @time = (0,0);
	my $sort_order = 3;
	my $w = 7; # base of fields' width
	
	ReadMode(q(cbreak));
	
	print qq(\033[2J);
	while (1) {
		my $char = ReadKey(-1);
		$i = 0 if (defined $char and lc($char) eq q(f));				# F - flush statistics
		$stop = !$stop if (defined $char and lc($char) eq q(s));			# S - start / stop
		$help = !$help if (defined $char and lc($char) eq q(h));			# H - show / hide help
		$opt->{packets} = !$opt->{packets} if (defined $char and lc($char) eq q(p));	# P - show / hide pps
		$opt->{bytes} = !$opt->{bytes} if (defined $char and lc($char) eq q(b));		# B - show / hide bps
		$h = ($h + 1) % @units if (defined $char and lc($char) eq q(u));			# U - toggle displayed units
		last if (defined $char and lc($char) eq q(q));					# Q - quit
		$opt->{direction} = q(in) if (defined $char and lc($char) eq q(i));		# I - sort by incoming traffic
		$opt->{direction} = q(out) if (defined $char and lc($char) eq q(o));		# O - sort by outgoing traffic
		$sort_order = (ord($char) - 49) % @sort_fields if (defined $char and ord($char) >= 49 and ord($char) <= 49 + $#sort_fields);	# 1..9
		my $dt = (Time::HiRes::time() - $time[0]);
		$time[0] = Time::HiRes::time();
		my $cmd = qq(sudo /sbin/iptables -t $opt->{table} -xvn -L $opt->{chain});
		open (my $IPT, q(-|), $cmd) or print_usage(qq(WARNING: Cannot open pipe '$cmd': $!));
		while (<$IPT>) {
			chomp;
			next unless m{\A \s* 
					(\d+) \s+	# pkts
					(\d+) \s+	# bytes
					.* /\*\s+	# /*
					(\S+)		# key
					_(in|out)	# in / out
					\s+\*/		# */
			}xms;
			if (!defined($res->{$3}->{$4}->{ppi})){		# packets per interval
				$res->{$3}->{$4}->{ppi} = ();
			}
			if (!defined($res->{$3}->{$4}->{bps})){		# bytes per interval
				$res->{$3}->{$4}->{bps} = ();
			}
			if (!defined($res->{$3}->{$4}->{avg})){		
				$res->{$3}->{$4}->{avg} = ();
			}
			if (!defined($res->{$3}->{$4}->{cur_avg})){
				$res->{$3}->{$4}->{cur_avg} = ();
			}
			if (!defined($res->{$3}->{$4}->{pkts})){
				$res->{$3}->{$4}->{pkts} = ();
			}
			if (!defined($res->{$3}->{$4}->{bytes})){
				$res->{$3}->{$4}->{bytes} = ();
			}
			if ( $i > 0 ){
				$res->{$3}->{$4}->{pkts}[$i] = $1;
				$res->{$3}->{$4}->{ppi}[$i-1] = ($1 - $res->{$3}->{$4}->{pkts}[$i-1])/$dt;
				$res->{$3}->{$4}->{bytes}[$i] = $2;
				$res->{$3}->{$4}->{bps}[$i-1] = ($2 - $res->{$3}->{$4}->{bytes}[$i-1])*8/$dt;
				$res->{$3}->{$4}->{avg}[$i-1] = sum(@{$res->{$3}->{$4}->{bps}})/@{$res->{$3}->{$4}->{bps}};
				$res->{$3}->{$4}->{cur_avg}[$i-1] = $res->{$3}->{$4}->{avg}[$i-1] != 0 ? $res->{$3}->{$4}->{bps}[$i-1]*100/$res->{$3}->{$4}->{avg}[$i-1] : 0;
			} else {
				$res->{$3}->{$4}->{pkts}[$i] = $1;
				$res->{$3}->{$4}->{bytes}[$i] = $2;
			}
		}
		close $IPT;
		if ($i > 1 and !$stop and !$help){
			my $j = 0;
			my $max_index = -1;
			my $min_index = -1;
			my $max_cur_avg_index = -1;
			if ((defined $opt->{total}) and (defined $res->{$opt->{total}})){
				$max_index = get_max(@{$res->{$opt->{total}}->{$opt->{direction}}->{bps}});
				$min_index = get_min(@{$res->{$opt->{total}}->{$opt->{direction}}->{bps}});
				$max_cur_avg_index = get_max(@{$res->{$opt->{total}}->{$opt->{direction}}->{cur_avg}});
			}
			my $output;
			for my $key (sort keys %$res) {
				for my $io (keys %{$res->{$key}}){
					$output->{$key}->{qq(cur_$io)} = $res->{$key}->{$io}->{bps}[$i-1]/1024**$h;
					$output->{$key}->{qq(avg_$io)} = $res->{$key}->{$io}->{avg}[$i-1]/1024**$h;
					$output->{$key}->{qq(max_$io)} = $max_index != -1 ? $res->{$key}->{$io}->{bps}[$max_index]/1024**$h : max(@{$res->{$key}->{$io}->{bps}})/1024**$h;
					$output->{$key}->{qq(min_$io)} = $min_index != -1 ? $res->{$key}->{$io}->{bps}[$min_index]/1024**$h : min(@{$res->{$key}->{$io}->{bps}})/1024**$h;
					$res->{$key}->{$io}->{cur_avg}[$i-1] = $output->{$key}->{qq(avg_$io)} != 0 ? $output->{$key}->{qq(cur_$io)}*100/$output->{$key}->{qq(avg_$io)} : 0;
					$output->{$key}->{qq(cur_avg_$io)} = $res->{$key}->{$io}->{cur_avg}[$i-1];
					$output->{$key}->{qq(max_avg_$io)} = $max_cur_avg_index != -1 ? $res->{$key}->{$io}->{cur_avg}[$max_cur_avg_index] : max(@{$res->{$key}->{$io}->{cur_avg}});
					$output->{$key}->{qq(ppi_cur_$io)} = $res->{$key}->{$io}->{ppi}[$i-1]/1000**$h;
					$output->{$key}->{qq(ppi_avg_$io)} = sum(@{$res->{$key}->{$io}->{ppi}})/@{$res->{$key}->{$io}->{ppi}}/1000**$h;
					$output->{$key}->{qq(ppi_min_$io)} = $min_index != -1 ? $res->{$key}->{$io}->{ppi}[$min_index]/1024**$h : min(@{$res->{$key}->{$io}->{ppi}})/1000**$h;
					$output->{$key}->{qq(ppi_max_$io)} = $max_index != -1 ? $res->{$key}->{$io}->{ppi}[$max_index]/1024**$h : max(@{$res->{$key}->{$io}->{ppi}})/1000**$h;
				}
			}
			$j = 0;
			# clear screen
			print qq(\033[1J);
			print qq(\033[1;1H);
			# print header
			print qq(Watching 'iptables -t $opt->{table} $opt->{chain}'\n);
			print qq(Refresh time is $opt->{interval} ms.\n);
			print qq(Stats period is $opt->{period} s.\n);
			print qq(Sorted $opt->{direction}put traffic by "$sort_fields[$sort_order]" field\n\n);
			my $format = qq(\033[37;%um%16s);
			$format .= $opt->{bytes} ? (q(%).($w*2).q(s)) x 4 . (q(%).($w*2+2).q(s)) x 2 : q();
			$format .= $opt->{packets} ? (q(%).($w*2).q(s)) x 4 : q();
			$format .= qq(\033[0m\n);
			my @columns = qw(1 name);
			@columns = $opt->{bytes} ? (@columns, qq(cur $units[$h]bps), qq(avg $units[$h]bps), qq(min $units[$h]bps), qq(max $units[$h]bps), qq(cur/avg), qq(max cur/avg)) : @columns;
			@columns = $opt->{packets} ? (@columns, qq(cur $units[$h]pps), qq(avg $units[$h]pps), qq(min $units[$h]pps), qq(max $units[$h]pps)) : @columns;
			printf $format, @columns;
			# print in/out line
			$format = qq(\033[37;1m).q(%3$16s);
			$format .= $opt->{bytes} ? (q(%1$).$w.q(s%2$).$w.q(s)) x 4 . (q(%1$).($w+1).q(s%2$).($w+1).q(s)) x 2 : q();
			$format .= $opt->{packets} ? (q(%1$).$w.q(s%2$).$w.q(s)) x 4 : q();
			$format .= qq(\033[0m\n);
			printf $format, q(in), q(out), q();
			# print numbers
			$format = qq(\033[37;%um%16s);
			$format .= $opt->{bytes} ? qq(%${w}u) x 8 . qq(%${w}u%%) x 4 : q();
			$format .= $opt->{packets} ? qq(%${w}u) x 8 : q();
			$format .= "\033[0m\n";
			for my $key (sort {$output->{$b}->{qq($sort_fields[$sort_order]_$opt->{direction})} <=> $output->{$a}->{qq($sort_fields[$sort_order]_$opt->{direction})}} keys %$output){
				@columns = qw(	cur_in cur_out avg_in avg_out min_in min_out max_in max_out cur_avg_in cur_avg_out max_avg_in max_avg_out 
						ppi_cur_in ppi_cur_out ppi_avg_in ppi_avg_out ppi_min_in ppi_min_out ppi_max_in ppi_max_out );
				printf $format, ($j%2)+2, $key, @{ $output->{$key} }{@columns};
				$j++;
			}
		} elsif ($help){
			print_hotkeys();
		}
		if ($period == 0 or $i < $period){
			$i++;
		} else {
			for my $key1 (keys %$res) {
				for my $key2 (keys %{$res->{$key1}}) {
					for my $key3 (keys %{$res->{$key1}->{$key2}}) {
					shift (@{$res->{$key1}->{$key2}->{$key3}});
					}	
				}
			}
		}
		$time[1] = Time::HiRes::time();
		$dt = $opt->{interval}*1000 - ($time[1] - $time[0])*10**6;
		$dt = $dt > 0 ? $dt : 0;
		Time::HiRes::usleep($dt);
	}
	ReadMode('normal');
}

sub main {
	GetOptions($opt,
		q(chain=s),
		q(table|t=s),
		q(interval=i),
		q(period=i),
		q(direction=s),
		q(total=s),
		q(unit=s),
		q(help),
		q(packets),
		q(bytes),
	) or print_usage(q(Wrong options!));
	
	check_options($opt);
	
	nload();
}

main();
