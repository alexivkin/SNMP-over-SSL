#!/usr/local/bin/perl -Tw
#
# SNMP SSL traffic decoding server
#
# Must be run as ROOT (uses port 443)
#
# 05.30.2002 v0.1 - start of the development
# 05.31.2002 v0.2 - keep alive SSL channel
# 06.03.2002 v0.3 - SSL channel down detecting/password/multithreaded
# 06.04.2002 v0.4 - Data reciept confirmation. Polished
# 06.20.2002 v0.5 - Routed output to a file. Trap creation routine.
# 06.24.2002 v0.6 - Use SNMP_util lib instead of a system call.
# 06.25.2002 v0.7 - Generates connection up/down traps on such events
# 06.26.2002 v0.8 - IPMaps for the unique node identification
# 06.27.2002 v0.9 - IPMaps were UNautomated
# 06.27.2002 v1.0 - First release version
# 08.09.2002 v1.1 - Fixed bug that was spawning new threads once in awhile
#
# Usage: $0 [0-5] - debugging
#
use SNMP_util;
use strict;
use Socket;
use Carp;
use IO::Handle;
use Net::SSLeay qw(sslcat die_now die_if_ssl_error);
BEGIN { $ENV{PATH} = '/usr/local/bin:/bin:/usr/bin' }
#
my $waitedpid=0;
#
# Functions and forward declarations
#
sub spawn;  # forward declaration
sub logmsg { print OF scalar localtime() . " " . $0 . "[" . $$ . "]: @_\n"; return 0 }
sub REAPER { $waitedpid = wait; $SIG{CHLD} = \&REAPER; logmsg "reaped $waitedpid" . ($? ? " with exit $?" : '') }
#
# Constants
#
my $CONUPTRAPEID = ".1.3.6.1.4.1.14027";				# Enterprise ID
my $CONUPTRAPNUM = "20";               			     		# Trap spec - ConnectionUp
my @CONUPTRAPVAL = (".1.3.6.1.4.1.14027.0.20","int","1"); 		# Event variable, type and a value
my $CONDOWNTRAPEID = ".1.3.6.1.4.1.14027";				# Enterprise ID
my $CONDOWNTRAPNUM = "21";               				# Trap spec - ConnectionDown
my @CONDOWNTRAPVAL = (".1.3.6.1.4.1.14027.0.21","int","1");	  	# Event variable, type and a value
#my $HOSTSFILE      = "/etc/hosts";        				# Where to keep all ip<->name maps
my $IPMAPNET 	   = 11;        					# Class A Net for the ipmap
my $OUTPUTFILE     = "/var/snmp/rnsnmprcv";    				# log
my $EOL = "\015\012";
#
# Local Vars setup
#
my $port = 443;
my $cert_pem = "/usr/local/etc/rnmscert.pem";
my $key_pem = "/usr/local/etc/rnmskey.pem";
my $our_ip = "\0\0\0\0";		# "\x7F\0\0\x01";
my $ctx;
my $trace = 0;
# my %ipmap; # hash to keep track of ip<->name resolver
#
# Open a log file
#
open (OF, ">>$OUTPUTFILE") || die "Cannot open file $OUTPUTFILE: $!";
autoflush OF,1;
#
# Parse parameters
#
logmsg "Loading server ...";
if ($#ARGV == 0 and $ARGV[0] =~ /^[0-5]$/){
	if ($ARGV[0] < 3){
		$trace=$ARGV[0];
	} else {
		$trace=2;
		$Net::SSLeay::trace = $ARGV[0]-2;
	}
	logmsg  "Debugging level set to $ARGV[0] ...";
}
#
# Load the ipmap
#
#logmsg "Loading IPMap..."  if $trace>1;
#open (HF, $HOSTSFILE) || logmsg "Cannot open file $HOSTSFILE: $!" || exit 1;
#my ($record,$ip,$host,@ippart,$ipmax);
#$ipmax=ip_atoi("$IPMAPNET.0.0.0");
#while (<HF>){
#	# get the uncommented part
#	$record = /^(.*?)#/ ? $1:$_;
#	next if !defined($record);
#	# get ip and the host name
#        ($ip,$host) = ($record =~ /.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([.\S]+)/);
#	next if !defined($ip) || !defined ($host);
#	# split it for the net portion
#	@ippart = split (/\./, $ip);
#	if ($ippart[0] == $IPMAPNET) {
#		# get the biggest IP so that we will start from there
#		$ipmax = ip_atoi($ip) if (ip_atoi($ip) > $ipmax);
#	}
#}
#close HF;
#
# Open hosts file for updating
#
#open (HF, ">>$HOSTSFILE") || logmsg "Cannot open file $HOSTSFILE: $!" || exit 1;
#autoflush HF,1;
#
# Create the socket and open a connection
#
my $our_serv_params = pack ('S n a4 x8', &AF_INET, $port, $our_ip);
socket (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
setsockopt(S, SOL_SOCKET, SO_REUSEADDR, pack("l", 1))   || die "setsockopt: $!";
bind (S, $our_serv_params)             or die "bind:   $! (port=$port)";
listen (S, 5)                          or die "listen: $!";
#
# Precharge SSLeay
#
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::randomize();
#
# Prepare SSL Environment
#
print "Creating SSL context...\n" if $trace>1;
$ctx = Net::SSLeay::CTX_new () or die_now("CTX_new ($ctx): $!\n");
print "Setting cert and RSA key...\n" if $trace>1;
Net::SSLeay::CTX_set_cipher_list($ctx,'ALL');
Net::SSLeay::set_cert_and_key($ctx, $cert_pem, $key_pem) or die "key";
logmsg "Server started on port $port." if $trace>1;
#
# Setup environment
#
my ($paddr, $old_out, $ssl, $line, @trapinfo);
my ($ent,$agent,$agentx,$gen,$spec,@vars);
my ($iaddr, $name, $iport);
$SIG{CHLD} = \&REAPER; #skip that for now
logmsg "Accepting connections...";
#
# Main connection cycle - wait for a TCP connection
#
for ( $waitedpid = 0; ($paddr = accept(NS,S)) || $waitedpid; $waitedpid = 0, close NS){

    next if $waitedpid and not $paddr;
    $old_out = select (NS); $| = 1; select ($old_out);
    ($iport,$iaddr) = sockaddr_in($paddr);
    ($name = gethostbyaddr($iaddr,AF_INET)) || ($name="unknown");
    logmsg "Connection from $name [ " . inet_ntoa($iaddr) . ":" . $iport . " ]";
    #
    # Code spawed for every successfull TCP connection
    #
    spawn sub {
    	$|=1;
        #
    	# Do SSL negotiation stuff
	#
    	print "Creating SSL session (cxt=`$ctx')...\n" if $trace>1;
    	$ssl = Net::SSLeay::new($ctx) or die_now("ssl new ($ssl): $!");
    	print "Setting fd (ctx $ctx, con $ssl)...\n" if $trace>1;
    	Net::SSLeay::set_fd($ssl, fileno(NS));
    	print "Entering SSL negotiation phase...\n" if $trace>1;
    	Net::SSLeay::accept($ssl);
    	die_if_ssl_error("ssl accept: ($!)");
    	logmsg "Secure Layer created...";
        #
    	# Connected. Expect a password.
    	#
    	$line = Net::SSLeay::read($ssl);
	#print $line;
    	if (!defined($line)) {
		logmsg "No password.";
    	} elsif ( not $line eq "RNPass") {
		logmsg "Bad password."
    	} else {
		logmsg "Password accepted. Ready for the data.";
		# Confirm password
		Net::SSLeay::write($ssl, "PassOK");
		#
		# Send a trap about a new SSL connection
		#
		_do(\&snmptrap,"localhost", $CONUPTRAPEID, "" . inet_ntoa($iaddr), "6", $CONUPTRAPNUM, @CONUPTRAPVAL);
		logmsg "Connection_up trap: $CONUPTRAPEID, " . inet_ntoa($iaddr) . ", 6, $CONUPTRAPNUM,", join (", ", @CONUPTRAPVAL)  if $trace>1;
		#
        	# Data exchange cycle
		#
		while (1){
			# Check for the client on the other side
			# May need to use sleep() here
			if (defined($line = Net::SSLeay::read($ssl))){
				if ( $line eq '' ) {
					last;
				}
				@trapinfo = split /#/ , $line;
				@trapinfo = split /\s+/ , $trapinfo[1];

				$ent = shift @trapinfo;
				$agent = shift @trapinfo;
				$gen = shift @trapinfo;
				$spec = shift @trapinfo;
				# split values to triplets of a variable, type and a value.
				@vars = (join(" ", @trapinfo) =~ /([\d\.]+)\s+(\w+)\s+([^"]+|"[^"]*")/g); #strict
				# @vars = (join(" ", @trapinfo) =~ /([\w\d\.:]+)\s+([\w\d\.:]+)\s+([\w\d\.:]+|"[^"]*")/g); #less strict
				logmsg "Incoming ... Trap info: $ent, $agent, $gen, $spec,", join (", ", @vars);
				# First check if the management system knows about the agent
				$agentx = $agent;
				$agentx =~ s/\./\-/g; # substitute - for .
				if (defined(gethostbyname("$name-$agentx"))){
					# if yes then use that ip
					$agent = join(".",unpack('C4',gethostbyname("$name-$agentx")));
					logmsg "Using $agent for $name-$agentx" if $trace>2;
				} else {
					# if not then try to get $name-unknown and log it
					logmsg "Unknown host $agent from $name";
					if (defined(gethostbyname("$name-unknown"))){
						$agent = join(".",unpack('C4',gethostbyname("$name-unknown")));
					} else {
						# use just $name if cannot resolve $name-unknown
						$agent = "". inet_ntoa($iaddr);
					}
					# if not then put it into the hash and the hosts file
					#$agent=ip_itoa(++$ipmax);
					#print HF "$agent $name-$agentx\n";
					#logmsg "Defined $agent for $name-$agentx" if $trace>2;
				}
				# Send a trap. Error handling is done within _do
				_do(\&snmptrap,"localhost", $ent, $agent, $gen, $spec, @vars);
				# Confirm data
				Net::SSLeay::write($ssl, "OK");
			} else {
				last;
			}
		     }
	        logmsg "Lost connection with $name [ " . inet_ntoa($iaddr) . ":" . $iport . " ]";
		#
		# Send a trap about a lost connection
		#
		_do(\&snmptrap,"localhost", $CONDOWNTRAPEID, "" . inet_ntoa($iaddr), "6", $CONDOWNTRAPNUM, @CONDOWNTRAPVAL);
		logmsg "Connection_down trap: $CONDOWNTRAPEID, " . inet_ntoa($iaddr) . ", 6, $CONDOWNTRAPNUM,", join (", ", @CONDOWNTRAPVAL)  if $trace>1;
	 }
	 logmsg "Tearing down the connection.";
	 Net::SSLeay::free ($ssl);
    };
    close NS;
}
Net::SSLeay::CTX_free ($ctx);
close S;
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
#
# Code to fork the child
#
sub spawn {
    my $coderef = shift;
    unless (@_ == 0 && $coderef && ref($coderef) eq 'CODE') {
       confess "usage: spawn CODEREF";
    }
    my $pid;
    if (!defined($pid = fork)) {
	logmsg "cannot fork: $!";
    	return;
    } elsif ($pid) {
    	logmsg "begat $pid";
    	return; # I'm the parent
    }
    # else I'm the child -- go spawn
#    open(STDIN,  "<&NS")   || die "can't dup client to stdin";
#    open(STDOUT, ">&NS")   || die "can't dup client to stdout";
    ## open(STDERR, ">&STDOUT") || die "can't dup stdout to stderr";
    &$coderef();
    exit;
}
# this funky wrapper is because SNMP_Session throws exceptions with
# warn(), which we need to catch, instead of letting them run
# roughshod over RNSNMPRCV output.
sub _do {
    my($subref, @args) = @_;
    my(@res,$err);
    $err = '';
    eval {
        local($SIG{'__WARN__'}) = sub { $err = $_[0]; die($err); };
        @res = &{$subref}(@args);
    };
    # do a little post processing on the overly wordy errors
    # that SNMP_Session gives us...
    if (defined($err) && $err ne '') {
        my(@err) = split(/\n\s*/, $err);
        if (defined($err[1]) && ($err[1] eq "no response received")) {
            my $host = (split(/: /,$err[2]))[1];
            $host =~ s/\)$//;
            $err = "No response from $host";
        } elsif ($#err+1 > 2) {
            my($code) = (split(/: /, $err[2]))[1];
            $err = "$err[1] $code.";
            if ($code eq "noSuchName") {
                my($oid) = $err[3];
                $oid =~ s/.*\((.*)\).*/$1/;
                $err .= " $oid";
            }
        } else {
            $err =~ s/\n//g;
        }
        logmsg("SNMP Error: $err");
    }
    return @res;
}



__END__
