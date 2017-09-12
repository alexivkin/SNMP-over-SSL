#!/usr/local/bin/perl -w
use RRDs;


my $rrd = "max2.rrd";
open X, ">/tmp/rrdfetch" || die "ops";
my $start = 86400;

	my $DAY=100;
	my ($rrdstart,$rrdstep,$rrdnames,$rrddata);
	my $endx=$start;
	my $startx;
	my $datatime=0;
	my $downtime=0;
	my $data;
	do {
		$startx = $endx;
		$endx   = $startx > $DAY ? $startx-$DAY:0;
		($rrdstart,$rrdstep,$rrdnames,$rrddata) = RRDs::fetch $rrd, "AVERAGE", "--start", "now-$startx", "--end", "now-$endx";
		my $ERROR1 = RRDs::error();
		do_log ("ERROR: $ERROR1") if $ERROR1 ;

    		foreach my $data (@$rrddata){
			print X "@$data[1]\n";
    		}
	} while ($endx > 0);
exit;