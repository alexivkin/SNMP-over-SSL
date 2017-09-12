# -*- perl -*-
#
# RNToolSet.pm - collection of various functions
#
# 07/19/02 - v0.1  development started
# 07/19/02 - v1.5c First release
#
#
package RNToolSet;

use RRDs 1.000101;
use RRD::File;
use Socket;
use strict;
############################################################################
#
# Constants
#
############################################################################
# Declaration (solving the problem of "variable will not stay shared")
use vars qw/$SMOKESTEP $SMOKEPINGS $LTHRESHOLD $IMAGESDIR $MAXROWWIDTH $MAXROWHEIGHT/;
use vars qw/$GREENBALL $REDBALL $BLACKBALL $YELLOWBALL $SMOKEPING/;
use vars qw/$ENTERPRISEOID $TRESHOLDVIOLATED $TRESHOLDSATISFIED/;
# Assignment
$ENTERPRISEOID 	   = ".1.3.6.1.4.1.14027";
$TRESHOLDVIOLATED  = ".4";
$TRESHOLDSATISFIED = ".5";
$SMOKEPINGS   = 20;	# number of smokeping pings
$LTHRESHOLD   = 0.002;  # Latency threshold (in sec)
$IMAGESDIR    = "/images"; # URL (!) relative images folder
$SMOKEPING    = "/cgi-bin/rnping.cgi?target="; # URL (!) relative smokeping link
$MAXROWWIDTH  = 5;	# max columns number
$MAXROWHEIGHT = 5; 	# max column height
$GREENBALL    = "<img src=\"$IMAGESDIR/grnball.gif\">";
$REDBALL      = "<img src=\"$IMAGESDIR/redball.gif\">";
$YELLOWBALL   = "<img src=\"$IMAGESDIR/ylwball.gif\">";
$BLACKBALL    = "<img src=\"$IMAGESDIR/blackball.gif\">";
############################################################################
#
# Functions
#
############################################################################
#
# Forward declarations
#
sub searchDBFolder($$);
#
# Prints an HTML page based on a given tempate and a given string
# (puts it in place of <##contents##> string form the template
# Params:
#	string - a template
#	string - contents
#
sub doHTMLTemplate($$){
   my $template = shift;
   my $string = shift;
   my $gQ = new CGI;
   print $gQ->header('text/html');
   my $line = $/;
   undef $/;
   open I, $template || print "<HTML><BODY>ERROR: Reading template $template: $!</BODY></HTML>";
   my $data = <I>;
   close I;
   $/ = $line;
   my ($header,$footer) = split(/<##contents##>/, $data);
   print "$header${$string}$footer";
}
#-----------------------------------------------------------------------------
#
# Returns a string with comments for a summary page
# Params:
#	none
# Returns:
#	a string
#
sub doComments(){
	my $a = "<p>A - Availability ($GREENBALL - node was up, all $SMOKEPINGS pings got throught, $YELLOWBALL - some pings were lost,  $REDBALL - node was down, all pings were lost)<br>\n";
	$a = "$a L - Latency ($GREENBALL - median RTT was always less than $LTHRESHOLD seconds, $YELLOWBALL - at times more than $LTHRESHOLD sec, $REDBALL - always more than $LTHRESHOLD sec)<br>\n";
	$a = "$a T - Thresholds ($GREENBALL - no threshold violations, $YELLOWBALL - thresholds were violated and satisfied, $REDBALL - thresholds were violated and not satisfied)<br></p>\n";
	$a = "$a &nbsp;<br>\n";
	return $a;
}
#-----------------------------------------------------------------------------
#
# Cache the logfile
# Params:
#       string - log file name
# Returns:
#	an array with the log (line per element)
#
sub cacheLog($){
	my $traplog = shift;
	my @logfile;
	open L, $traplog  || print "ERROR: Reading page template: $!" || return @logfile;
	my $i=0;
	while (<L>){
		next if (!(/\[\d+\].*/)); # skip if not in correct format
		$logfile[$i++]=$_;
	}
	return @logfile;
}
#-----------------------------------------------------------------------------
#
# Returns index of the first line from the log file that is within a specified timeframe
# Params:
#	ref to an array - log cache
#	int - timeframe, sec before now
# Returns:
#	element num or -1 if there is no data in a specified timeframe
#
sub scrollLog($$){
	my $logfile=shift;
	my $timeframe=shift;
	my $i;
	my $foundflag=0;
	for ($i=0;$i < $#$logfile; $i++){
		if ($logfile->[$i] =~ /\[(\d+)\].*/){ # if correct format get the timeframe
			$foundflag=1;
			last if ((time-$1) <= $timeframe);
		}
	}
	return ($foundflag) ? $i:-1;
}
#-----------------------------------------------------------------------------
#
# Calculates smokeping and cricket statistics for a given timeframe. Returns that in an html format as a string
# Params:
#	ref to hash - hosts hash
#	ref to an array - log cache
#	int - timeframe, sec before now
#       string - smokeping DB root folder
# Returns:
#	statistics - Statistics
#
sub doStatistics($$$$){
	my $hosts=shift; # by ref
	my $logfile=shift; # by ref
	my $timeframe=shift;
	my $rootfolder=shift;
	my $out; # output string
	my $ix=0;
	my $jx=0;
	my $tablestart="<table><tr bgcolor=\"#135192\"><td><p>Node</p></td><td><p>A</p></td><td><p>L</p></td><td><p>T</p></td></tr>\n";
	# scroll the log to the relevant data
	my $logi = scrollLog($logfile, $timeframe);
	# filter and hashify the log file for the faster search
	my %filteredlog;
	if ($logi != -1) {
		my ($junk,$agent,$ent,$spec);
 		for(my $i=$logi; $i < $#$logfile; $i++){
 			$_=$logfile->[$i];
			next if (!(/\[\d+\].*/)); # skip if not in correct format
                        # parse the line to get the trap id
			($junk,$ent,$agent,$spec) =  /(.+)\[.+\](.+)#(.+)#.+#(.+)#.+/;
			next if ($ent ne $ENTERPRISEOID);
			if ($spec eq $TRESHOLDVIOLATED) {
				if (!defined($filteredlog{$agent})) {
					$filteredlog{$agent}=1;
				} else {
					$filteredlog{$agent}++;
				}
			}
			if ($spec eq $TRESHOLDSATISFIED) {
				if (!defined($filteredlog{$agent})) {
					$filteredlog{$agent}=-1;
				} else {
					$filteredlog{$agent}--;
				}
			}
		}
	}
	# start the big and the sub tables
	$out = "<table><tr valign=\"top\"><td>\n$tablestart";
	# start listing nodes with the data
	my ($img, $ERROR, $val, $linker, $keyip);
	foreach my $key (sort (keys(%{$hosts}))) {
		$val = $hosts->{$key};
		$keyip = join(".",unpack("C4",gethostbyname($key)));
		$val =~ /$rootfolder\/(.+)\.rrd/;
		$linker = $1;
		$linker =~ tr/\//\./;
		$out = "$out<tr><td><p class=\"menu\"><a href=\"$SMOKEPING$linker\"><font color=white size=2>$key</font></a></p></td>";
		# fetch the availability data
		my ($rrdstart,$rrdstep,$rrdnames,$rrddata) = RRDs::fetch $val , "AVERAGE", "--start", "now-$timeframe"."sec";
		$ERROR = RRDs::error();
	    	die ("ERROR: $ERROR") if $ERROR;
		# scan the data
		my ($data,$loss,$median);
		my $aflag=0;
		my $lflag=0;
	    	for(my $i=0; $i < $#$rrddata; $i++){
		    	$data=$rrddata->[$i]; # this is not a mistake, RRD gives us numb of elem-1 as a size
		    	$loss=@$data[1];
			$median=@$data[2];
			# check availability
			if ($aflag != 1 && defined($loss) && $loss >= $SMOKEPINGS){ # do only if data is defined and it is ok
				$aflag=1;	# node was down
				last; 		# and that is terminal
			}
			if ($aflag == 0 && defined($loss) && $loss > 0 && $loss < $SMOKEPINGS){ # do only if data is defined and it is ok
				$aflag=2;	# node was loosing packets
			}
			# check latency
			if ($lflag == 0 && defined($median) && $median >= $LTHRESHOLD ){
				$lflag=1;	# node was not ok all the time
			}
			if ($lflag == 1 && defined($median) && $median < $LTHRESHOLD ){
				$lflag=2;	# node was ok at times
				last; 		# and that is terminal
			}
	    	}
		# img can be on or off
		$out = "$out<td>$GREENBALL</td>\n"  if $aflag == 0;
		$out = "$out<td>$REDBALL</td>\n"    if $aflag == 1;
		$out = "$out<td>$YELLOWBALL</td>\n" if $aflag == 2;
		if ($aflag != 1){
			$out = "$out<td>$GREENBALL</td>\n"  if $lflag == 0;
			$out = "$out<td>$REDBALL</td>\n"    if $lflag == 1;
			$out = "$out<td>$YELLOWBALL</td>\n" if $lflag == 2;
		} else { # if node is down then always red latency
			$out = "$out<td>$REDBALL</td>\n";
		}
 		# read the log file for threshold analysis
		# if there is a data for this node
 		if ($logi != -1 && defined($filteredlog{$keyip})) {
			$out = "$out<td>$REDBALL</td>\n"    if $filteredlog{$keyip} > 0; # unsatisfied threshold violations
			$out = "$out<td>$YELLOWBALL</td>\n" if $filteredlog{$keyip} <= 0;# satisfied threshold violations
		} else {
			$out = "$out<td>$GREENBALL</td>\n";
		}
		$out = "$out</tr>\n";

		# now split the tables
		if ($ix++ >= $MAXROWHEIGHT-1){
			if ($jx++ >= $MAXROWWIDTH-1){
				$out = "$out</table></td></tr><tr valign=\"top\"><td>$tablestart";
				$ix=0;
				$jx=0;
			} else {
				$out = "$out</table></td><td>$tablestart";
				$ix=0;
			}
		}
	}
	# end the big and the sub tables
	$out = "$out</table></td></tr></table>\n";
	return $out;
}
#-----------------------------------------------------------------------------
#
# Folder traverser. Looks for rrd files, fills a hash with a node name and a corresponding rrd file
# Params:
#	string with a start dir
#	ref to a resulting hash
#
sub searchDBFolder($$){
	my $curdir=shift;
	my $curhash=shift; # by ref
	return if (!opendir(DIR, $curdir));
	my @entities=grep(!/^\..*/, readdir DIR);
	foreach my $entity (@entities) {
		if (-d "$curdir/$entity"){
			# if a folder then recurse (if chdir was successfull)
			searchDBFolder("$curdir/$entity",$curhash);
		} elsif ( -f "$curdir/$entity" && ($entity =~ /\.rrd$/)){
			 my ($fname) = ($entity =~ /(.*)\.rrd$/);
			 $curhash->{$fname}="$curdir/$entity";
		}
	}
	closedir(DIR);
}
#-----------------------------------------------------------------------------
#
# Cache the traps configuration file
# Params:
#       string - traps.conf file name
# Returns:
#	hash - {"EntOID.EventID" = "Trap string"}
#
sub cacheTrapsConf($){
	my $trapsconf = shift;
	my (%traps, $record,$oid,$id,$message);
	open T, $trapsconf || print "Cannot open file $trapsconf: $!" || return %traps;
	while (<T>){
		$record = /^(.*?)#/ ? $1:$_;
		next if !defined($record);
		# get the oid, id and the message
	        ($oid,$id, $message) = ($record =~ /(.*?)\s+(\d*)\s+(.*)/);
		next if !defined($oid) || !defined ($id) || !defined ($message);
		# add to the hash
		$traps{"$oid.$id"}=$message;
	}
	close T;
	return %traps;
}
#-----------------------------------------------------------------------------
#
# Formats traps from logfile to fit traps.conf description. Outputs in a reverse order (newest first).
# Params:
#       ref to array  - cached logfile
#	ref to hash   - cached traps.conf file
#	int - starting line in a logfile (from its end)
# Returns:
#	string - formatted traps in html format
#
sub doFormatTraps($$$){
	my $logfile = shift;
	my $traps = shift;
	my $line = shift;
	my $result = "<table>\n"; # resulting output
	my ($format, $timestamp,$ent,$agent,$gen,$spec,$body, @vars, $listvar, @page);
	my $i=0;
	for (my $j = $#$logfile - $line; $j < $#$logfile; $j++) { # browse thru the logfile
		$_ =$logfile->[$j];
		next if (!(/\[\d+\].*/)); # skip if not in correct format
		($timestamp,$ent,$agent,$gen,$spec,$body) =  /(.+)\[.+\](.+)#(.+)#(.+)#(.+)#(.+)/;
		$page[$i]= "<tr>";
		# split values to triplets of a variable, type and a value.
		@vars = ($body =~ /[\d\.]+\s+=\s+[\w:]+\s+([^"]+|"[^"]*")/g); #strict
		# @vars = (join(" ", @trapinfo) =~ /([\w\d\.:]+)\s+([\w\d\.:]+)\s+([\w\d\.:]+|"[^"]*")/g); #less strict
		$format=$traps->{"$ent$spec"}; # assume that $spec is in \.\d format
		$page[$i]= "$page[$i]<td><p>$timestamp</p></td>\n";
		$page[$i]= "$page[$i]<td align=right><p><i><b>". (gethostbyaddr(inet_aton($agent),AF_INET))[0] ."</b></p></i></td><td align=left><p><b> [$agent]</b></p></td>\n";
		# check if trap is defined
		$listvar=join(", ",@vars);
		if (!defined($format)){
			$page[$i]= "$page[$i]<td><p>Unknown trap: $ent, $spec, $listvar</p></td>";
		} else {
			$format =~ s/\$\$/\$/g;
			$format =~ s/\$!/$listvar/g;
			$format =~ s/\$@/$#vars/g;
			$format =~ s/\$(\d+)/$vars[$1]/g;
			$page[$i]= "$page[$i]<td><p>$format</p></td>";
		}
		# finish up the line and move on
		$page[$i]= "$page[$i]</tr>\n";
		$i++;
	}
	# print the list in a reverse order (newest first)
	while ($i-- > 0){
		 $result = "$result$page[$i]\n";
	}
	$result = "$result</table>";
	return $result;
}
