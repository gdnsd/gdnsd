package Net::DNS::RR::SOA;
#
# $Id: SOA.pm 932 2011-10-26 12:40:48Z willem $
#
use strict;
BEGIN {
    eval { require bytes; }
}
use vars qw(@ISA $VERSION);

@ISA     = qw(Net::DNS::RR);
$VERSION = (qw$LastChangedRevision: 932 $)[1];

sub new {
	my ($class, $self, $data, $offset) = @_;

	if ($self->{"rdlength"} > 0) {
		($self->{"mname"}, $offset) = Net::DNS::Packet::dn_expand($data, $offset);
		($self->{"rname"}, $offset) = Net::DNS::Packet::dn_expand($data, $offset);

		@{$self}{qw(serial refresh retry expire minimum)} = unpack("\@$offset N5", $$data);
	}

	return bless $self, $class;
}

sub new_from_string {
	my ($class, $self, $string) = @_;

	if ($string) {
		$string =~ tr/()//d;

		# XXX do we need to strip out comments here now that RR.pm does it?
		$string =~ s/;.*$//mg;

		@{$self}{qw(mname rname serial refresh retry expire minimum)} = $string =~ /(\S+)/g;

		$self->{'mname'} = Net::DNS::stripdot($self->{'mname'});
		$self->{'rname'} = Net::DNS::stripdot($self->{'rname'});
	}

	return bless $self, $class;
}

sub rdatastr {
	my $self = shift;
	my $rdatastr;

	if (exists $self->{"mname"}) {
		$rdatastr  = "$self->{mname}. $self->{rname}. (\n";
		$rdatastr .= "\t" x 5 . "$self->{serial}\t; Serial\n";
		$rdatastr .= "\t" x 5 . "$self->{refresh}\t; Refresh\n";
		$rdatastr .= "\t" x 5 . "$self->{retry}\t; Retry\n";
		$rdatastr .= "\t" x 5 . "$self->{expire}\t; Expire\n";
		$rdatastr .= "\t" x 5 . "$self->{minimum} )\t; Minimum TTL";
	} else {
		$rdatastr = '';
	}

	return $rdatastr;
}

sub rr_rdata {
	my ($self, $packet, $offset) = @_;
	my $rdata = "";

	# Assume that if one field exists, they all exist.  Script will
	# print a warning otherwise.

	if (exists $self->{"mname"}) {
		$rdata .= $packet->dn_comp($self->{"mname"}, $offset);
		$rdata .= $packet->dn_comp($self->{"rname"},  $offset + length $rdata);

		$rdata .= pack("N5", @{$self}{qw(serial refresh retry expire minimum)});
	}

	return $rdata;
}


sub serial {
	use integer;
	my $self = shift;

	return $self->{serial} || 0 unless @_;			# current/default value

	my $value = shift;					# replace if in sequence
	return $self->{serial} = $value if _ordered( $self->{serial}, $value );

	# unwise to assume 32-bit hardware, or that integer overflow goes unpunished
	my $serial = 0xFFFFFFFF & ( 0 + $self->{serial} );
	return $self->{serial} ^= 0xFFFFFFFF if ( $serial & 0x7FFFFFFF ) == 0x7FFFFFFF;	   # wrap
	return $self->{serial} = $serial + 1;			# increment
}


sub _ordered($$) {				## irreflexive partial ordering (32-bit)
	use integer;
	my ( $a, $b ) = @_;

	return defined $b unless defined $a;			# ( undef, any )
	return 0 unless defined $b;				# ( any, undef )

	# unwise to assume 32-bit hardware, or that integer overflow goes unpunished
	if ( $a < 0 ) {						# translate $a<0 region
		$a = ( $a ^ 0x80000000 ) & 0xFFFFFFFF;		#  0	 <= $a < 2**31
		$b = ( $b ^ 0x80000000 ) & 0xFFFFFFFF;		# -2**31 <= $b < 2**32
	}

	if ( $a < $b ) {
		return $a > ( $b - 0x80000000 );
	} else {
		return $b < ( $a - 0x80000000 );
	}
}


sub _normalize_dnames {
	my $self=shift;
	$self->_normalize_ownername();
	$self->{'mname'}=Net::DNS::stripdot($self->{'mname'}) if defined $self->{'mname'};
	$self->{'rname'}=Net::DNS::stripdot($self->{'rname'}) if defined $self->{'rname'};
}


sub _canonicalRdata {
    my $self=shift;
    my $rdata = "";

    # Assume that if one field exists, they all exist.  Script will
    # print a warning otherwise.

    if (exists $self->{"mname"}) {
		$rdata .= $self->_name2wire(lc($self->{"mname"}));
		$rdata .= $self->_name2wire(lc($self->{"rname"}));
		$rdata .= pack("N5", @{$self}{qw(serial refresh retry expire minimum)});
	}

	return $rdata;
}


1;
__END__

=head1 NAME

Net::DNS::RR::SOA - DNS SOA resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for DNS Start of Authority (SOA) resource records.

=head1 METHODS

=head2 mname

    print "mname = ", $rr->mname, "\n";

Returns the domain name of the original or primary nameserver for
this zone.

=head2 rname

    print "rname = ", $rr->rname, "\n";

Returns a domain name that specifies the mailbox for the person
responsible for this zone.


=head2 serial

    print "serial = ", $rr->serial, "\n";
    $new_serial = $rr->serial(value);

Unsigned 32 bit version number of the original copy of the zone.
Zone transfers preserve this value.

RFC1982 defines a strict (irreflexive) partial ordering for zone
serial numbers. The serial number will be incremented unless the
replacement value argument satisfies the ordering constraint.


=head2 refresh

    print "refresh = ", $rr->refresh, "\n";

Returns the zone's refresh interval.

=head2 retry

    print "retry = ", $rr->retry, "\n";

Returns the zone's retry interval.

=head2 expire

    print "expire = ", $rr->expire, "\n";

Returns the zone's expire interval.

=head2 minimum

    print "minimum = ", $rr->minimum, "\n";

Returns the minimum (default) TTL for records in this zone.


=head1 Zone Serial Number Management

The internal logic of the serial() method offers support for
several widely used zone serial numbering policies.

=head2 Strictly Sequential

    $successor = $soa->serial( SEQUENTIAL );

The existing serial number is incremented modulo 2**32 because
the value returned by the auxiliary SEQUENTIAL() function can never
satisfy the serial number ordering constraint.

=head2 Date Encoded

    $successor = $soa->serial( YYYYMMDDxx );

The 32 bit value returned by the auxiliary YYYYMMDDxx() function
will be used if it satisfies the ordering constraint, otherwise
the existing serial number will be incremented as above.

Serial number increments must be limited to 100 per day for the
date information to remain useful.

=head2 Time Encoded

    $successor = $soa->serial( time );

The 32 bit value returned by the perl CORE::time() function will
be used if it satisfies the serial number ordering constraint,
otherwise the existing value will be incremented as above.


=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr.

Portions Copyright (c) 2002-2004 Chris Reinhardt.

Portions Copyright (c) 2011 Dick Franks.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC 1035 Section 3.3.13, RFC1982

=cut
