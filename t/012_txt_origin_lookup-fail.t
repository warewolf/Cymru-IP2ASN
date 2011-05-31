#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

use Cymru::IP2ASN;

my $cymru = new Cymru::IP2ASN;

my ($one) = $cymru->_cymru_txt_lookup("origin","abcd");
isnt(ref($one),"ARRAY","cymru sample origin lookup fail returns non-arrayref");
is ($one,undef,"cymru sample origin lookup fail returns undef");

my $two = $cymru->origin("216.90.108.31");
is ($two->asn(),23028,"cymru sample origin scalar context object asn value");

my (@three) = $cymru->origin("216.90.108.31");
is($three[0]->asn(),23028,"cymru sample origin list context object asn value");
