#!/usr/bin/perl

use Test::More qw(no_plan);

use Cymru::IP2ASN;


my $cymru = new Cymru::IP2ASN;

my ($return) = $cymru->_cymru_txt_lookup("peer", "31.108.90.216");
like ($return->[0],qr/\Q216.90.108\E/,"cymru sample peer lookup 216.90.108.31");
