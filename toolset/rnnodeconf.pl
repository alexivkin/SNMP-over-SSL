#!/usr/local/bin/perl -w
#
# Configuration script for rnsnmpfwd, rnsnmprcv and smokeping
#
# 06/27/02 - v0.1 development started
# 06/28/02 - v0.2 postfixes
#
#
use strict;
#
# Constants
#
my $SPINGFILE   = "/usr/local/smokeping/etc/config";   	# where all incoming traps are kept
my $FWDFILE = "/usr/local/etc/rnsnmp.conf";		# file with a management server`s name
my $HOSTSFILE = "/tmp/hosts.add";       		# hosts
my $SPINGBAKFILE = "/tmp/smokeping.add";
my $FWDBAKFILE = "/tmp/rnsnmp.add"; 
my $EOL = "\015\012";
#
# Local Vars
#
my ($mip,$cip,$cname,$maxip);
my ($nname,$nip,%nhash);
#
# Actual data input
#
print "Quick sanity check before we start...\n";
open (FF, ">$FWDBAKFILE") || die "Cannot open >$FWDBAKFILE: $!";
open (HF, ">$HOSTSFILE") || die "Cannot open >$HOSTSFILE: $!";
open (SF, ">$SPINGBAKFILE") || die "Cannot open >$SPINGBAKFILE: $!";
print "Tell me management station`s max ip (use rnmaxip.pl): ";
$maxip=<STDIN>;
$maxip =~ s/(.*)\n/$1/;
$maxip = ip_atoi($maxip);
print "Okeydokey. Welcome. Lets start with customer's name: ";
$cname=<STDIN>;
$cname =~ s/(.*)\n/$1/;
print "Good boy. How about management server's ip\n (hit enter if you just need to ADD nodes): ";
$mip=<STDIN>;
$mip =~ s/(.*)\n/$1/;
if ($mip ne "") {
	print "Good boy. Now tell me my outside(internet) ip: ";
	$cip=<STDIN>;
	$cip =~ s/(.*)\n/$1/;
	print "Wow, that was easy. Now lets enter nodes to be managed...\n";
}
while (1){
	print "Node`s IP (hit enter now to end): ";
	$nip=<STDIN>;
	$nip =~ s/(.*)\n/$1/;
	last if $nip eq "";
	print "Node`s frendly name (hit enter to use IP): ";
	$nname=<STDIN>;
	$nname=~ s/(.*)\n/$1/;
	$nname=$nip if $nname eq "";
	$nhash{$nip}=$nname;
}
#
# Update rnsnmpfwd
#
if ($mip ne "") {
	print FF "$mip";
	close FF;
}
#
# Update smokeping and rnsnmprcv
#
if ($mip ne "") {
	print HF ip_itoa($cip) . " $cname\n";
	print HF ip_itoa(++$maxip) . " $cname-unknown\n";
}
if ($mip ne "") {
	print SF "+ $cname\n\n";
	print SF "menu = $cname\n";
	print SF "title = $cname\n\n";
}
my $keyx;
while (my ($key,$value) = each %nhash) {
	$keyx = $key;
	$keyx =~ s/\./\-/g; # substitute - for .
	print HF ip_itoa(++$maxip) . " $cname-$keyx\n";
	print SF "++ $value\n\n";
	print SF "menu = $value\n";
	print SF "title = $value\n";
	print SF "host = $key\n\n";
}
close SF;
close HF;

print "\nOk, I`v done as much as I can. Now that`s what YOU have to do:";
print "\n1. Copy the files I have created:";
print "\n   cp $FWDBAKFILE >> $FWDFILE";
print "\n   cat $SPINGBAKFILE >> $SPINGFILE";
print "\n2. Configure rnsnmprcv on the management station by doing this:";
print "\n   scp $HOSTSFILE $mip:/tmp";
print "\n   ssh $mip";
print "\n   Once there do that:";
print "\n   cat $HOSTSFILE >> /etc/hosts";
print "\n3. Reload smokeping by doing this:";
print "\n   rm -rf /usr/local/smokeping/var/*";
print "\n   /etc/init.d/smokeping restart";
print "\n4. Reload rnsnmpfwd by doing this:";
print "\n   rm /var/snmp/rn*";
print "\n   /etc/init.d/snmpfwd restart";
print "\n5. And finally... Configure freaken Cricken. Good luck.\n";
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


__END__
