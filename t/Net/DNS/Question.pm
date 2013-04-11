package Net::DNS::Question;

#
# $Id: Question.pm 971 2011-12-14 10:39:30Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 971 $)[1];


=head1 NAME

Net::DNS::Question - DNS question record

=head1 SYNOPSIS

    use Net::DNS::Question;

    $question = new Net::DNS::Question('example.com', 'A', 'IN');

=head1 DESCRIPTION

A Net::DNS::Question object represents a record in the question
section of a DNS packet.

=cut


use strict;
use integer;
use Carp;

use Net::DNS;
use Net::DNS::DomainName;


=head1 METHODS

=head2 new

    $question = new Net::DNS::Question('example.com', 'A', 'IN');
    $question = new Net::DNS::Question('example.com');

    $question = new Net::DNS::Question('192.0.32.10', 'PTR', 'IN');
    $question = new Net::DNS::Question('192.0.32.10');

Creates a question object from the domain, type, and class passed as
arguments. One or both type and class arguments may be omitted and
will assume the default values shown above.

RFC4291 and RFC4632 IP address/prefix notation is supported for
queries in both in-addr.arpa and ip6.arpa namespaces.

=cut

sub new {
	my $self   = bless {}, shift;
	my $qname  = shift;
	my $qtype  = uc( shift || '' );
	my $qclass = uc( shift || '' );

	# tolerate (possibly unknown) type and class in zone file order
	unless ( exists $Net::DNS::classesbyname{$qclass} ) {
		( $qtype, $qclass ) = ( $qclass, $qtype )
				if exists $Net::DNS::classesbyname{$qtype};
		( $qtype, $qclass ) = ( $qclass, $qtype ) if $qtype =~ /CLASS/;
	}
	unless ( exists $Net::DNS::typesbyname{$qtype} ) {
		( $qtype, $qclass ) = ( $qclass, $qtype )
				if exists $Net::DNS::typesbyname{$qclass};
		( $qtype, $qclass ) = ( $qclass, $qtype ) if $qclass =~ /TYPE/;
	}

	# if argument is an IP address, do appropriate reverse lookup
	if ( defined $qname and $qname =~ m/:|\d$/ ) {
		if ( my $reverse = _dns_addr($qname) ) {
			$qname = $reverse;
			$qtype ||= 'PTR';
		}
	}

	$self->{name}  = new Net::DNS::DomainName1035($qname);
	$self->{type}  = Net::DNS::typesbyname( $qtype || 'A' );
	$self->{class} = Net::DNS::classesbyname( $qclass || 'IN' );

	return $self;
}


=head2 decode

    $question = decode Net::DNS::Question(\$data, $offset);

    ($question, $offset) = decode Net::DNS::Question(\$data, $offset);

Decodes the question record at the specified location within a DNS
wire-format packet.  The first argument is a reference to the buffer
containing the packet data.  The second argument is the offset of
the start of the question record.

Returns a Net::DNS::Question object and the offset of the next
location in the packet.

An exception is raised if the object cannot be created
(e.g., corrupt or insufficient data).

=cut

use constant QFIXEDSZ => length pack 'n2', (0) x 2;

sub decode {
	my $self = bless {}, shift;
	my ( $data, $offset ) = @_;

	( $self->{name}, $offset ) = decode Net::DNS::DomainName1035(@_);

	my $next = $offset + QFIXEDSZ;
	die 'corrupt wire-format data' if length $$data < $next;
	@{$self}{qw(type class)} = unpack "\@$offset n2", $$data;

	return wantarray ? ( $self, $next ) : $self;
}


=head2 encode

    $data = $question->encode( $offset, $hash );

Returns the Net::DNS::Question in binary format suitable for
inclusion in a DNS packet buffer.

The optional arguments are the offset within the packet data where
the Net::DNS::Question is to be stored and a reference to a hash
table used to index compressed names within the packet.

=cut

sub encode {
	my $self = shift;

	return pack 'a* n2', $self->{name}->encode(@_), @{$self}{qw(type class)};
}


=head2 qname, zname

    $qname = $question->qname;
    $zname = $question->zname;

Returns the question name attribute.  In dynamic update packets,
this attribute is known as zname() and refers to the zone name.

=cut

sub qname {
	my $self = shift;

	return $self->{name}->identifier unless @_;
	croak 'method invoked with unexpected argument';
}

sub zname { &qname; }


=head2 qtype, ztype

    $qtype = $question->qtype;
    $ztype = $question->ztype;

Returns the question type attribute.  In dynamic update packets,
this attribute is known as ztype() and refers to the zone type.

=cut

sub type {
	my $self = shift;

	return Net::DNS::typesbyval( $self->{type} ) unless @_;
	croak 'method invoked with unexpected argument';
}

sub qtype { &type; }
sub ztype { &type; }


=head2 qclass, zclass

    $qclass = $question->qclass;
    $zclass = $question->zclass;

Returns the question class attribute.  In dynamic update packets,
this attribute is known as zclass() and refers to the zone class.

=cut

sub class {
	my $self = shift;

	return Net::DNS::classesbyval( $self->{class} ) unless @_;
	croak 'method invoked with unexpected argument';
}

sub qclass { &class; }
sub zclass { &class; }


=head2 print

    $object->print;

Prints the record to the standard output.  Calls the string() method
to get the string representation.

=cut

sub print {
	print shift->string, "\n";
}


=head2 string

    print "string = ", $question->string, "\n";

Returns a string representation of the question record.

=cut

sub string {
	my $self = shift;

	return join "\t", $self->{name}->string, $self->qclass, $self->qtype;
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


sub _dns_addr {				## Map IP address into reverse lookup namespace
	local $_ = shift;

	# IP address must contain address characters only
	return undef unless m#^[a-fA-F0-9:./]+$#;

	# arg looks like IPv4 address: map to in-addr.arpa space
	if (m#(^|:.*:)((^|\d+\.)+\d+)(/(\d+))?$#) {
		my @parse = split /\./, $2;
		my $prefx = $5 || @parse << 3;
		my $last = $prefx > 24 ? 3 : ( $prefx - 1 ) >> 3;
		return join '.', reverse( ( @parse, (0) x 3 )[0 .. $last] ), 'in-addr.arpa';
	}

	# arg looks like IPv6 address: map to ip6.arpa space
	if (m#^((\w*:)+)(\w*)(/(\d+))?$#) {
		my @parse = split /:/, ( reverse "0${1}0${3}" ), 9;
		my @xpand = map { /./ ? $_ : ('0') x ( 9 - @parse ) } @parse;	 # expand ::
		my $prefx = $5 || @xpand << 4;			# implicit length if unspecified
		my $hex = pack 'A4' x 8, map { $_ . '000' } ('0') x ( 8 - @xpand ), @xpand;
		my $len = $prefx > 124 ? 32 : ( $prefx + 3 ) >> 2;
		return join '.', split( //, substr( $hex, -$len ) ), 'ip6.arpa';
	}

	return undef;
}


1;
__END__

########################################

=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2003,2006-2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::DomainName>, L<Net::DNS::Packet>,
RFC 1035 Section 4.1.2

