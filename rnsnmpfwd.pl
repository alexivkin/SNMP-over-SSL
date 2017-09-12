#!/usr/local/bin/perl -w
#
# SNMP SSL traffic encoding client
#
# 05/30/02 - v0.1 development started
# 05/31/02 - v0.2 SSL channel keep alive 
# 06/03/02 - v0.3 SSL channel down detection/password
# 06/04/02 - v0.4 Read/send text snmp traps from a file. Polished
# 06/19/02 - v0.5 Reading config from a file. File trimming.
#		  Limit stress on CPU in the data cycle. Pipe STDOUT to a file
# 06/20/02 - v0.6 Limited debug output. Data parsing. Trap time stamp check.
# 06/21/02 - v0.7 Fixed data parsing for multiple values
# 06/24/02 - v0.8 Fixed data type parsing for SNMP_util lib used by the server.
#		  Fixed log file opening problem. Additional debug output.
#		  Fixed bug that was killing it if the connection is down.
# 06/26/02 - v0.9 Fixed bug with DATAMAXAGE = 1 day. Displays data before it drops it.
# 06/27/02 - v1.0 First release version
# 08/09/02 - v1.1 Fixed bug that was spawning new threads on the server once in awhile
#
# TODO: Optimize/Speedup
#
# Usage: $0 [0-3] - debug level
#
use strict;
use Net::SSLeay qw(die_now die_if_ssl_error);
use IO::Handle;
use Socket;
#
# Functions and forward declarations
#
sub getdata;
sub isolddata;
sub logmsg { print OF scalar localtime() . " " . $0 . "[" . $$ . "]: @_\n"; return 0 }
#
# Constants
#
my $DATAMAXAGE = 604800;		        # Maximum data age in seconds (a week)
my $SIZELIMIT  = 1024*1024*512;			# 1Mb
my $SNMPFILE   = "/var/snmp/snmptraps";   	# where all incoming traps are kept
my $SERVERFILE = "/usr/local/etc/rnsnmp.conf";  # file with a server`s name
my $OUTPUTFILE = "/var/snmp/rnsnmpfwd";         # log
my $CHANNELSLEEPTIME = 10;                     	# Seconds between tries to open a channel
my $DATASLEEPTIME = 10;                     	# Seconds between new data tests
my $EOL = "\015\012";
#
# Local Vars
#
my ($host,$port, $iaddr, $paddr, $proto, $line, $ssl, $errorm, $data, $firstrun);
#
# Setup
#
$firstrun= 1;
$data    = '';
$errorm  = '';
$host    = '';
$port    = 443;  
#
# Load server`s name and open a log file
#
open (OF, ">>$OUTPUTFILE") || die "Cannot open file $OUTPUTFILE: $!";
autoflush OF,1;
open (CF, $SERVERFILE) || logmsg "Cannot open file $SERVERFILE: $!" || exit 1;
$host=<CF> || logmsg "Cannot get ssl server`s name" || exit 1;
chomp $host;
close CF;
#
# Parse parameters
#
logmsg "Loading client ..."; 
if (defined $ARGV[0]) {
	$Net::SSLeay::trace = $ARGV[0]; 
	logmsg "Setting debug level to $ARGV[0] ...";
}
#
# TCP Socket pre charge
#
$iaddr   = inet_aton($host) || logmsg "No host: $host" || exit 1;
$paddr   = sockaddr_in($port, $iaddr);
$proto   = getprotobyname('tcp');
#
# SSL Precharge
#
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::randomize();
#
# Prepare SSL Environment
#
my $ctx = Net::SSLeay::CTX_new() || die_now('CTX_new');
Net::SSLeay::CTX_set_cipher_list($ctx,'ALL');
#
# Open data file
#
open (DF, $SNMPFILE) || logmsg "Cannot open file $SNMPFILE"  || exit 1;
#
# Main data transfer cycle
#
logmsg "Client started.";
while (1) {
	#
	# Entering SSL negotiation phase...
	#
	logmsg "Openning channel..." if $Net::SSLeay::trace > 0;
	while (1){
		#
		# Open TCP Connection
		#
		$errorm ne "" || socket(NSOCKET,&PF_INET,&SOCK_STREAM, $proto) || ($errorm="socket: $!");
		$errorm ne "" || connect (NSOCKET, $paddr) || ($errorm="Cannot connect to [$host:$port] : $!");
		$errorm ne "" || select  (NSOCKET); $| = 1; select (STDOUT);
		#
		# Open SSL Connection
		#
		$errorm ne "" || ($ssl = Net::SSLeay::new($ctx)) || ($errorm="ssl new: $!");
		$errorm ne "" || Net::SSLeay::set_fd($ssl, fileno(NSOCKET)) || ($errorm="set fd ($ssl): $!");
		# Following line may freeze up if server is not accepting SSL connections (i.e TCP up/SSL not)!
		$errorm ne "" || Net::SSLeay::connect($ssl) || ($errorm="cannot establish secure connection with the management station: $!");
		# exit if the channel was opened
	        $errorm eq "" && last; 
		# if not say so
		logmsg($errorm);
		$errorm = "";
		logmsg "Cannot open the SSL channel, still trying...";
		sleep $CHANNELSLEEPTIME;
		# Collect lost junk in memory here (free)
		if ($firstrun eq 0 && isolddata($data) eq 1){
			logmsg "This data is too old: $data. Loading data...";
			$data=getdata();
		}
	}
	#
	# Connected. Send the password.
	#
	logmsg "Channel opened...";
	Net::SSLeay::write($ssl, "RNPass");
	$line = Net::SSLeay::read($ssl);
	# connnection lost or a fake if read not "PassOK"
	(defined $line && $line eq "PassOK") || logmsg "Unknown response. Server is a fake!" || next;
	#
	# Now check the data in our hands...
	#
	if ($firstrun eq 1) {
		$firstrun=0;
		logmsg "Loading data for the first time...";
		$data=getdata();
	}
	while (isolddata($data) eq 1){
		logmsg "This data is too old: $data. Loading data...";
		$data=getdata();
	}
	# 
	# Send data unless channel is closed
	#
	logmsg "Entering data cycle..." if $Net::SSLeay::trace > 0;
	while (1) {
		# send the data
		logmsg "Sending data...";
		# connnection lost if cant write
		Net::SSLeay::write($ssl, $data) || last;
		logmsg "Data sent." if $Net::SSLeay::trace > 2;
		logmsg "Confirming data..." if $Net::SSLeay::trace > 1;
		$line = Net::SSLeay::read($ssl);
		# connnection lost if read not "OK"
		(defined $line && $line eq "OK") || last;
		logmsg "Data confirmed." if $Net::SSLeay::trace > 2;
		logmsg "Loading data...";
		$data=getdata();
		logmsg "Data loaded." if $Net::SSLeay::trace > 2;
	}
	logmsg "Leaving data cycle..." if $Net::SSLeay::trace > 0;
	# kill the connection explicitly
	shutdown(NSOCKET, 2);# close connection
}

logmsg "Closing connection. Exiting.\n";
shutdown(NSOCKET, 2);# close connection

Net::SSLeay::free ($ssl);
close(NSOCKET) || die "close: $!";
Net::SSLeay::CTX_free ($ctx);
exit;
################################################################################
#
# Checks if a data is too old
#
sub isolddata {
	shift =~ /(\d+)#/;
	logmsg "Checking data timestamp...Now:", time, " Data: $1 Difference:", (time-$1) if $Net::SSLeay::trace > 2;
	return 1 if ((time - $1) > $DATAMAXAGE);
	return 0;
}
#
# Loads the data from snmptraps file or waits for one and then loads
#
sub getdata {
	my $datax;
	my $invaliddata=1;
	do {  
		#
		# This loop sits at the end of a file and checks for new data
		#
		while (not ($datax=<DF>)) {
			logmsg "No new data ... sleeping ..." if $Net::SSLeay::trace > 2;
			# check if the data file is too big
			if ((stat($SNMPFILE))[7] > $SIZELIMIT) {
				# trunicate the file
				logmsg "$SNMPFILE is too big. Archieving ...";
				close (DF);
				# remove old archieve if exists
				unlink "$SNMPFILE.old" if (-e "$SNMPFILE.old");
				rename ($SNMPFILE,"$SNMPFILE.old");
				# create a file
				open (TF, ">" . $SNMPFILE);
				close (TF);
				# open it for reading
				open (DF, $SNMPFILE) || logmsg "Something terrible has happend to $SNMPFILE: $!" || exit 1;
				logmsg "Waiting for new data...";
			}
			sleep $DATASLEEPTIME;
		}
		#
		# Parse new data
		#
		if ($datax=~/\[(\d+)\](.*)/){   # if correct format
			my $time=$1;
			my @temp=split(/#/,$2);
			# fix trap id number
			$temp[3]=substr($temp[3],1,length($temp[3])-1);
			# parse trap value
			my $value=$temp[4];
			# horror! 
			$_ = $value;
			# special typefitting for SNMP_util lib
			$value =~ s/=\sINTEGER:/int/g;
			$value =~ s/=\sUNSIGNED:/int/g;
			$value =~ s/=\sCOUNTER32:/int/g;
			$value =~ s/=\sSTRING:/string/g;
			$value =~ s/=\sHEX STRING:/string/g;
			$value =~ s/=\sDECIMAL STRING:/string/g;
			$value =~ s/=\sNULLOBJ:/oid/g;
			$value =~ s/=\sOBJID:/oid/g;
			$value =~ s/=\sTIMETICKS:/int/g;
			$value =~ s/=\sIPADDRESS:/ipaddr/g;
			$value =~ s/=\sBITS:/string/g;
			# add double quotes
			$temp[4]="\'\'";
			$temp[5]=$value;
			$datax= $time . "#" . join(" ",@temp);
			if (defined($time) && defined($temp[0]) && defined($temp[1]) && defined($temp[2]) &&
		            defined($temp[3]) && defined($temp[4]) && defined($temp[5]) ){
				$invaliddata=0;
			} else {
				logmsg "Error parsing new data.";
			}
		}
	} while ($invaliddata);	
	return $datax;
}

__END__
