package Net::DNS::DomainName;
use base qw(Net::DNS::Domain);

#
# $Id: DomainName.pm 964 2011-12-02 10:23:51Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 964 $)[1];


=head1 NAME

Net::DNS::DomainName - DNS domain name wire representation

=head1 SYNOPSIS

    use Net::DNS::DomainName;

    $object = new Net::DNS::DomainName('example.com');
    $name = $object->name;
    $data = $object->encode;

    ( $object, $next ) = decode Net::DNS::DomainName( \$data, $offset );

=head1 DESCRIPTION

The Net::DNS::DomainName module implements the concrete representation
of DNS domain names used within DNS packets.

Net::DNS::DomainName defines methods for encoding and decoding wire
format octet strings as defined in RFC1035. All other behaviour,
including the new() constructor, is inherited from Net::DNS::Domain.

The Net::DNS::DomainName1035 and Net::DNS::DomainName2535 packages
implement disjoint domain name subtypes which provide the name
compression and canonicalisation specified by RFC1035 and RFC2535.
These are necessary to meet the backward compatibility requirements
introduced by RFC3597.

=cut


use strict;
use integer;
use Carp;


=head1 METHODS

=head2 new

    $object = new Net::DNS::DomainName('example.com');

Creates a domain name object which identifies the domain specified
by the character string argument.


=head2 decode

    $object = decode Net::DNS::DomainName( \$buffer, $offset, $hash );

    ( $object, $next ) = decode Net::DNS::DomainName( \$buffer, $offset, $hash );

Creates a domain name object which represents the DNS domain name
identified by the wire-format data at the indicated offset within
the data buffer.

The argument list consists of a reference to a scalar containing the
wire-format data and specified offset. The optional reference to a
hash table provides improved efficiency of decoding compressed names
by exploiting already cached compression pointers.

The returned offset value indicates the start of the next item in the
data buffer.

=cut

sub decode {
	my $self   = bless {}, shift;
	my $buffer = shift;					# reference to data buffer
	my $offset = shift || 0;				# offset within buffer
	my $cache  = shift || {};				# hashed objectref by offset

	my $buflen = length $$buffer;
	my $index  = $offset;

	while ( $index < $buflen ) {
		my $header = unpack( "\@$index C", $$buffer );
		unless ($header) {				# terminal empty label
			return wantarray ? ( $self, ++$index ) : $self;

		} elsif ( $header < 0x40 ) {			# non-terminal label
			push( @{$self->{label}}, substr( $$buffer, ++$index, $header ) );
			$index += $header;

		} elsif ( $header < 0xC0 ) {			# deprecated extended label types
			croak 'unimplemented label type';

		} else {					# compression pointer
			my $link = 0x3FFF & unpack( "\@$index n", $$buffer );
			croak 'corrupt compression pointer' unless $link < $offset;
			$self->{origin} = $cache->{$link} ||= decode Net::DNS::DomainName( $buffer, $link, $cache );
			return wantarray ? ( $self, $index + 2 ) : $self;
		}
	}
	croak 'corrupt wire-format data';
}


=head2 encode

    $data = $object->encode;

Returns the wire-format representation of the domain name suitable
for inclusion in a DNS packet buffer.

=cut

sub encode {
	join '', map pack( 'C a*', length($_), $_ ), shift->_wire, '';
}


########################################

sub _wire {				## Generate list of wire-format labels
	my $self = shift;

	my @label = @{$self->{label}} if $self->{label};
	my @suffx = $self->{origin}->_wire if $self->{origin};
	return ( @label, @suffx );
}


########################################

package Net::DNS::DomainName1035;
use base qw(Net::DNS::DomainName);

=head1 Net::DNS::DomainName1035

Net::DNS::DomainName1035 implements a subclass of domain name
objects which are to be encoded using the compressed wire format
defined in RFC1035.

    use Net::DNS::DomainName;

    $object = new Net::DNS::DomainName1035('compressible.example.com');
    $data   = $object->encode( $offset, $hash );

    ( $object, $next ) = decode Net::DNS::DomainName1035( \$data, $offset );

Note that RFC3597 implies that the RR types defined in RFC1035
section 3.3 are the only types eligible for compression.


=head2 encode

    $data = $object->encode( $offset, $hash );

Returns the wire-format representation of the domain name suitable
for inclusion in a DNS packet buffer.

The optional arguments are the offset within the packet data where
the domain name is to be stored and a reference to a hash table used
to index compressed names within the packet.

If the hash reference is undefined, encode() returns the lowercase
uncompressed canonical representation defined in RFC2535(8.1).

=cut

sub encode {
	my $self   = shift;
	my $offset = shift || 0;				# offset in data buffer
	my $hash   = shift;					# hashed offset by name

	return join '', map pack( 'C a*', length($_), _lc($_) ), $self->_wire, '' unless defined $hash;

	my @labels = $self->_wire;
	my $data   = '';
	while (@labels) {
		my $name = join( '.', @labels );

		return $data . pack( 'n', 0xC000 | $hash->{$name} ) if defined $hash->{$name};

		my $label  = shift @labels;
		my $length = length $label;
		$data .= pack( 'C a*', $length, $label );

		next unless $offset < 0x4000;
		$hash->{$name} = $offset;
		$offset += 1 + $length;
	}
	$data .= chr(0);
}


sub _lc {
	local $_ = shift;
	tr [\101-\132] [\141-\172];
	return $_;
}


########################################

package Net::DNS::DomainName2535;
use base qw(Net::DNS::DomainName);

=head1 Net::DNS::DomainName2535

Net::DNS::DomainName2535 implements a subclass of domain name
objects which are to be encoded using uncompressed wire format.

Note that RFC3597, and latterly RFC4034, specifies that the lower
case canonical encoding defined in RFC2535 is to be used for RR
types defined prior to RFC3597.

    use Net::DNS::DomainName;

    $object = new Net::DNS::DomainName2535('incompressible.example.com');
    $data   = $object->encode( $offset, $hash );

    ( $object, $next ) = decode Net::DNS::DomainName2535( \$data, $offset );


=head2 encode

    $data = $object->encode( $offset, $hash );

Returns the uncompressed wire-format representation of the domain
name suitable for inclusion in a DNS packet buffer.

If the hash reference is undefined, encode() returns the lowercase
canonical form defined in RFC2535(8.1).

=cut

sub encode {
	my ( $self, $offset, $hash ) = @_;

	return join '', map pack( 'C a*', length($_), $_ ), $self->_wire, '' if defined $hash;

	return join '', map pack( 'C a*', length($_), _lc($_) ), $self->_wire, '';
}


sub _lc {
	local $_ = shift;
	tr [\101-\132] [\141-\172];
	return $_;
}


1;
__END__


########################################

=head1 COPYRIGHT

Copyright (c)2009-2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Domain>, RFC1035, RFC2535,
RFC3597, RFC4034

=cut

