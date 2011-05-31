#!/usr/bin/perl

use Test::More qw(no_plan);

use Cymru::IP2ASN;


my $cymru = new Cymru::IP2ASN;

my $return = $cymru->_cymru_txt_lookup("asn", "AS23028");
like ($return,qr/\Q23028\E/,"cymru sample asn lookup AS23028");
