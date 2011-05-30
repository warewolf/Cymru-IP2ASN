#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

use Cymru::IP2ASN;

my $cymru = new Cymru::IP2ASN;

my ($return) = $cymru->_cymru_txt_lookup("origin","abcd");
isnt(ref($return),"ARRAY","cymru sample origin lookup fail returns non-arrayref");
is ($return,undef,"cymru sample origin lookup fail returns undef");

my $origin = $cymru->origin("216.90.108.31");
foreach my $orig (@$origin) {
print Data::Dumper->Dump([$orig],[qw($orig)]);
print "Origin ASN: ",$orig->asn(),"\n";
}
