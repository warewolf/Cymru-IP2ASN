#!/usr/bin/perl

use Test::More qw(no_plan);

use Cymru::IP2ASN;
use Data::Dumper;


my $cymru = new Cymru::IP2ASN;

my $one = $cymru->_cymru_txt_lookup("origin6","8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.b.0.6.8.4.1.0.0.2");
like ($one,qr/\Q2001:4860\E/,"cymru sample origin6 lookup nibbled 2001:4860:b002::68");

my @two = $cymru->_cymru_txt_lookup("origin6","8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.b.0.6.8.4.1.0.0.2");
like ($two[0],qr/\Q2001:4860\E/,"cymru sample origin6 lookup nibbled 2001:4860:b002::68");
