#!/usr/bin/perl -w

# Quick dirty hack for manual testing, generates multicast HTCP packets
#
# Usage:
#  ./pktgen.pl http://something.example.com/foo/bar/baz 43
# (43 is the number of HTCP CLR packets generated)
#
# port, multicast addr, and local source addr are hardcoded below...

use strict;
use IO::Socket::INET;

my $url = $ARGV[0];
my $iter = $ARGV[1] || 1;

my $mcport = 4827;
my $mcaddr = "239.128.0.112";
my $ifaddr = "127.0.0.1";

# roughly translated from SquidUpdate.php

my $sock = IO::Socket::INET->new(Proto => 'udp', LocalAddr => $ifaddr, PeerAddr => $mcaddr, PeerPort => $mcport);
die "Can't make socket: $!" unless $sock;

my $htcp_spec = pack('na4na*na8n', 4, 'HEAD', length($url), $url, 8, 'HTTP/1.0', 0);
my $htcp_dlen = 8 + 2 + length($htcp_spec);
my $htcp_len = 4 + $htcp_dlen + 2;

foreach my $n (1..$iter) {
    my $htcp_packet = pack('nxxnCxNxxa*n', $htcp_len, $htcp_dlen, 4, $iter, $htcp_spec, 2);
    my $sendrv = send($sock, $htcp_packet, 0);
    die "send() gave retval $sendrv: $!" unless $sendrv = length($htcp_packet);
}
