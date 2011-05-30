#!/usr/bin/perl

use Test::More qw(no_plan);

BEGIN {
  use_ok('Cymru::IP2ASN');
}

diag("Testing Cymru::IP2ASN $Cymru::IP2ASN::VERSION, Perl $], $^X");
