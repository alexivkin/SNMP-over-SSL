#!/usr/local/bin/perl -w
#
# Parse /etc/hosts to get maximum ip taken from the IPMap space
#
# 06/27/02 - v0.1 development started and ended
#
#
my $HOSTSFILE      = "/etc/hosts";        				# Where to keep all ip<->name maps
my $IPMAPNET 	   = 11;        					# Class A Net for the ipmap
#
# Get the maximum ip available from hosts
#
open (HF, $HOSTSFILE) || die "Cannot open file $HOSTSFILE: $!";
my ($record,$ip,$host,@ippart,$ipmax);
$ipmax=ip_atoi("$IPMAPNET.0.0.0");
while (<HF>){
	# get the uncommented part
	$record = /^(.*?)#/ ? $1:$_;
	next if !defined($record);
	# get ip and the host name 
        ($ip,$host) = ($record =~ /.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([.\S]+)/);
	next if !defined($ip) || !defined ($host);
	# split it for the net portion
	@ippart = split (/\./, $ip);
	if ($ippart[0] == $IPMAPNET) {
		# get the biggest IP so that we will start from there
		$ipmax = ip_atoi($ip) if (ip_atoi($ip) > $ipmax);
	}
}
close HF;
print "Max IP: ", ip_itoa($ipmax), "\n";
exit;

#
# Convert IP from a string to an int
#
sub ip_atoi {
	shift =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/; #split incoming
	return ((((($1<<8)+$2)<<8)+$3)<<8)+$4;
}
#
# Convert IP from an int to a string
#
sub ip_itoa {
	my $ip=shift;
	return (($ip>>24) . "." . (($ip>>16) & 255) . "." . (($ip>>8) & 255) . "." . ($ip & 255));
}
