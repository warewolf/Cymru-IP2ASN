# vim: ts=4 sw=4 foldmethod=marker filetype=perl
package Cymru::IP2ASN;
use strict;
use warnings;
use Data::Dumper;

use Net::DNS; # to query Cymru
use Net::IP::CMatch; # to perform matches quickly
use Net::IP; # to manipulate IP addresses

use Cymru::IP2ASN::Origin;
use Cymru::IP2ASN::Origin6;
use Cymru::IP2ASN::Peer;
use Cymru::IP2ASN::ASN;

our $VERSION = "0.0.1";

sub new {
  my ($class) = shift;
  my $self = {};
  bless $self,$class;
  $self->{_resolver} = Net::DNS::Resolver->new(
	tcp_timeout => 1, udp_timeout => 1,
    #nameservers=>[qw(127.0.0.1)]
  );
  $self->{_netip} = Net::IP->new("0.0.0.0");
  return $self;
};

sub origin {
  my ($self) = shift;
  my ($query) = @_;
  $self->{_netip}->set($query);

  # Net::IP appends .ip6.arpa and .in-addr.arpa, we need to remove it.
  my $reversed = $self->{_netip}->reverse_ip();
  $reversed =~ s/\.[^\.]+\.arpa\.$//;
  my @text_records = $self->_cymru_txt_lookup("origin",$reversed);
  my @return;
  map { push @return,Cymru::IP2ASN::Origin->new($_) } @text_records;
  if (scalar @return) {
    return wantarray ? @return : $return[0];
  } else {
    return undef;
  }
  return undef;
}

sub origin6 {
  my ($self) = shift;
  my ($query) = @_;
  $self->{_netip}->set($query);

  # Net::IP appends .ip6.arpa and .in-addr.arpa, we need to remove it.
  my $reversed = $self->{_netip}->reverse_ip();
  $reversed =~ s/\.[^\.]+\.arpa\.$//;
  my @text_records = $self->_cymru_txt_lookup("origin6",$reversed);
  my @return;
  map { push @return,Cymru::IP2ASN::Origin6->new($_) } @text_records;
  if (scalar @return) {
    return wantarray ? @return : $return[0];
  } else {
    return undef;
  }
  return undef;
}


sub peer {
  my ($self) = shift;
  my ($query) = @_;
  $self->{_netip}->set($query);

  # Net::IP appends .ip6.arpa and .in-addr.arpa, we need to remove it.
  my $reversed = $self->{_netip}->reverse_ip();
  $reversed =~ s/\.[^\.]+\.arpa\.$//;
  my @text_records = $self->_cymru_txt_lookup("peer",$reversed);
  my @return;
  map { push @return,Cymru::IP2ASN::Peer->new($_) } @text_records;
  if (scalar @return) {
    return wantarray ? @return : $return[0];
  } else {
    return undef;
  }
  return undef;
}

sub asn {
  my ($self) = shift;
  my ($query) = @_;
  my @return;

  my @text_records = $self->_cymru_txt_lookup("asn",$query);
  map { push @return,Cymru::IP2ASN::ASN->new($_) } @text_records;
  if (scalar @return) {
    return wantarray ? @return : $return[0];
  } else {
    return undef;
  }
  return undef;
}

# perform a TXT record lookup
# Parameters: Cymru record type, query prefix
# Result:
#   success + records:
#     arrayref of text record responses on success, undef on failure.
#   success (no records):
#     undef
#
#   failure: 

sub _cymru_txt_lookup {
  my ($self) = shift;
  my ($type,$string) = @_;
  my @return;

  # fixup type "asn" -> "" because asn.asn.cymru.com doesn't work.
  my $fqdn = sprintf("%sasn.cymru.com",$type eq "asn" ? "" : $type.".");

  # prepend string to FQDN
  my $name = sprintf("%s.%s",$string,$fqdn);

  # do the nslookup
  my $query = $self->{_resolver}->query($name,"TXT");

  if ($query) {
    # successful query.  Extract TXT records
    foreach my $rr ( grep { $_->type eq 'TXT' } $query->answer() ) {
      push @return,$rr->char_str_list;
    }
    # return undef if successful query, but no records
    # otherwise return arrayref
    if (scalar @return) {
      return wantarray ? @return : "@return";
    } else {
      return undef;
    }
    return scalar @return ? @return : undef;
  } else {
	# failed query
    if ($self->{_resolver}->errorstring() ne "NXDOMAIN") {
      # we had some kind of problem, return it
	  return $self->{_resolver}->errorstring;
    } else {
      # NXDOMAIN is quite common if an invalid search is requested
      return undef;
    }
  }
  # we shouldn't get here
  return undef;
}

# http://www.team-cymru.org/Services/ip-to-asn.html#dns
#
# The DNS daemon is designed for rapid reverse lookups, much in the same way 
# as RBL lookups are done. DNS has the added advantage of being cacheable and
# based on UDP so there is much less overhead. Similar to the whois TCP based
#  daemon, there are three IPv4 zones available, and one for IPv6:
#
# *  origin.asn.cymru.com
# * origin6.asn.cymru.com
# *    peer.asn.cymru.com
# *         asn.cymru.com
#
# The origin.asn.cymru.com zone is used to map an IP address or prefix to a
#  corresponding BGP Origin ASN.
#
# The origin6.asn.cymru.com zone is used to map an IPv6 address or prefix to a
# corresponding BGP Origin ASN.
#
# The peer.asn.cymru.com zone is used to map an IP address or prefix to the
# possible BGP peer ASNs that are one AS hop away from the BGP Origin ASN's
# prefix.
#
# The asn.cymru.com zone is used to determine the AS description of a given
# BGP ASN.
#
# All DNS-based queries should be made by pre-pending the reversed octets of
# the IP address of interest to the appropriate zone listed above, demonstrated
# in the following examples:
#
# $ dig +short 31.108.90.216.origin.asn.cymru.com TXT
# "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
#
# The same query could be expressed as:
#
# $ dig +short 108.90.216.origin.asn.cymru.com TXT
# "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
#
# IPv6 queries are formed by reversing the nibbles of the address, and placing dots between each nibble, just like an IPv6 reverse DNS lookup, except against origin6.asn.cymru.com instead of ip6.arpa. Note that you must pad out all omitted zeroes in the IPv6 address, so this can get quite long! For example, to look up 2001:4860:b002::68, you would issue the following query:
#
# $ dig +short 8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.b.0.6.8.4.1.0.0.2.origin6.asn.cymru.com. TXT
# "15169 | 2001:4860::/32 | US | arin | 2005-03-14"
#
# You can considerably shorten your query if you assume that the long runs of zeroes are in the host portion of the address (as is often the case with IPv6 addresses:
#
# $ dig +short 2.0.0.b.0.6.8.4.1.0.0.2.origin6.asn.cymru.com. TXT
# "15169 | 2001:4860::/32 | US | arin | 2005-03-14"
#
# To query for a given IP/prefix peer ASNs, one would use the peer.asn.cymru.com zone as follows:
#
# $ dig +short 31.108.90.216.peer.asn.cymru.com TXT
# "701 1239 3549 3561 7132 | 216.90.108.0/24 | US | arin | 1998-09-25"
#
# When there are multiple Origin ASNs or Peer ASNs, they will all be included in the same TXT record such as in the example above.
#
# Notice that the format is very similar to the data returned in the verbose whois based query. The major difference is that the AS Description information has been omitted. In order to return the ASN Description and additional info, one use:
#
# $ dig +short AS23028.asn.cymru.com TXT
# "23028 | US | arin | 2002-01-04 | TEAMCYMRU - SAUNET"
#
# If a given prefix does not exist in the table, the daemon will return a standard NXDOMAIN response (domain does not exist). 
#
1;
