#!/usr/bin/perl

use Test::More qw(no_plan);

use Cymru::IP2ASN;
use Data::Dumper;


my $cymru = new Cymru::IP2ASN;

my $one = $cymru->_cymru_txt_lookup("origin","31.108.90.216");
is(ref($one),"","scalar context returns string");

my @two = $cymru->_cymru_txt_lookup("origin","31.108.90.216");
is(ref(\@two),"ARRAY","list context returns array");

my ($fail) = $cymru->_cymru_txt_lookup("origin","abcd");
print Data::Dumper->Dump([$fail],[qw($fail)]);
is(ref($fail),undef,"unsuccessful query returns non-reference");
