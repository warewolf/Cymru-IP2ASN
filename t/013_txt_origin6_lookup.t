#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

use Cymru::IP2ASN;

my $cymru = new Cymru::IP2ASN;

my ($one) = $cymru->_cymru_txt_lookup("origin6","abcd");
isnt(ref($one),"ARRAY","cymru sample origin6 lookup fail returns non-arrayref");
is ($one,undef,"cymru sample origin6 lookup fail returns undef");

my $two = $cymru->origin6("2001:4860:b002::68");
is ($two->asn(),15169,"cymru sample origin6 scalar context object asn value");

my (@three) = $cymru->origin6("2001:4860:b002::68");
is($three[0]->asn(),15169,"cymru sample origin6 list context object asn value");
