use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Cymru::IP2ASN',
    AUTHOR              => 'Richard <cymru-ip2asn@richardharman.com>',
    VERSION_FROM        => 'lib/Cymru/IP2ASN.pm',
    ABSTRACT_FROM       => 'lib/Cymru/IP2ASN.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Cymru-IP2ASN-*' },
);

