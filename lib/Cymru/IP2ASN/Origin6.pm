package Cymru::IP2ASN::Origin6;

sub new {
  my ($class) = shift;

  my $txt_record = shift;

  my $self = {};
  bless $self,$class;
  $self->_parse($txt_record);
  return $self;
}

sub _parse {
  my ($self,$txt_record) = @_;
  @$self{qw(asn cidr cc nic date)}=split(m/\Q | \E/,$txt_record);
  return 1;
}

sub asn {
  my ($self) = shift;
  return $self->{asn};
}


1;
