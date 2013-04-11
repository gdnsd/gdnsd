package Net::DNS::Domain;

#
# $Id: Domain.pm 964 2011-12-02 10:23:51Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 964 $)[1];


=head1 NAME

Net::DNS::Domain - Domain Name System domains

=head1 SYNOPSIS

    use Net::DNS::Domain;

    $domain = new Net::DNS::Domain('example.com');
    $name   = $domain->name;

=head1 DESCRIPTION

The Net::DNS::Domain module implements a class of abstract DNS
domain objects with associated class and instance methods.

Each domain object instance represents a single DNS domain which
has a fixed identity throughout its lifetime.

Internally, the primary representation is a (possibly empty) list
of ASCII domain name labels, and optional link to an arbitrary
origin domain object topologically closer to the DNS root.

The presentation form of the domain name is generated on demand
and the result cached within the object.

=cut


use strict;
use integer;
use Carp;


use constant ASCII => eval {
	require Encode;
	Encode::find_encoding('ASCII');				# return encoding object
} || 0;

use constant UTF8 => eval {
	die if Encode::decode_utf8( chr(91) ) ne '[';		# specifically not UTF-EBCDIC
	Encode::find_encoding('UTF8');				# return encoding object
} || 0;

use constant LIBIDN => eval {
	require Net::LibIDN;					# tested and working
	UTF8 && Net::LibIDN::idn_to_ascii( pack( 'U*', 20013, 22269 ), 'utf-8' ) eq 'xn--fiqs8s';
} || 0;


=head1 METHODS

=head2 new

    $object = new Net::DNS::Domain('example.com');

Creates a domain object which represents the DNS domain specified
by the character string argument. The argument consists of a
sequence of labels delimited by dots.

A character preceded by \ represents itself, without any special
interpretation.

Arbitrary 8-bit codes can be represented by \ followed by exactly
three decimal digits.
Character code points are ASCII, irrespective of the character
coding scheme employed by the underlying platform.

Argument string literals should be delimited by single quotes to
avoid escape sequences being interpreted as octal character codes
by the Perl compiler.

The character string presentation format follows the conventions
for zone files described in RFC1035.

=cut

use vars qw($ORIGIN);

sub new {
	my $self = bless {}, shift;
	local $_ = shift;
	croak 'domain identifier undefined' unless defined $_;

	$self->{origin} = $ORIGIN if $ORIGIN && not /\.$/;	# dynamically scoped $ORIGIN

	if (/\\/) {
		s/\\\\/\\092/g;					# disguise escaped escape
		s/\\\./\\046/g;					# disguise escaped dot
		@{$self->{label}} = map _unescape( _encode_ascii($_) ), split /\.+/;

	} elsif ( $_ ne '@' ) {
		@{$self->{label}} = split /\056+/, _encode_ascii($_);
	}

	foreach ( @{$self->{label}} ) {
		next if ( length($_) || croak 'unexpected null domain label' ) < 64;
		carp length($_) . ' octet domain label truncated';
		substr( $_, 63 ) = '';
	}
	return $self;
}


=head2 name

    $name = $domain->name;

Returns the domain name as a character string corresponding to the
"common interpretation" to which RFC1034, 3.1, paragraph 9 alludes.

Character escape sequences are used to represent a dot inside a
domain name label and the escape character itself.

Domain names containing Unicode characters are supported if the
Net::LibIDN module is installed.

Any non-printable code point is represented using the appropriate
numerical escape sequence.

=cut

sub name {
	local $_ = &identifier;
	return $_ unless LIBIDN;
	return $_ unless /xn--/;

	my $self = shift;
	return $self->{name} ||= UTF8->decode( Net::LibIDN::idn_to_unicode( $_, 'utf-8' ) || return $_ );
}


=head2 fqdn

    @fqdn = $domain->fqdn;

Returns a character string containing the fully qualified domain
name, including the trailing dot.

=cut

my $dot = _decode_ascii( pack 'C', 46 );

sub fqdn {
	local $_ = &name;
	return /[$dot]$/o ? $_ : $_ . $dot;			# append trailing dot
}


=head2 identifier

    $identifier = $domain->identifier;

Identifies the domain by means of its uninterpreted A-label form of
domain name.

=cut

sub identifier {
	my $self = shift;

	return $self->{ident} if $self->{ident};

	my @label = map _decode_ascii( _escape($_) ), @{$self->{label}} if $self->{label};

	return $self->{ident} = join( $dot, @label, $self->{origin}->identifier ) if $self->{origin};

	return $self->{ident} = join( $dot, @label ) || $dot;
}


=head2 label

    @label = $domain->label;

Identifies the domain by means of a list of domain labels.

=cut

sub label {
	my $self = shift;

	my @label = map _decode_ascii( _escape($_) ), @{$self->{label}} if $self->{label};

	return @label unless $self->{origin};
	return ( @label, $self->{origin}->label );
}


=head2 string

    $string = $object->string;

Returns a character string containing the fully qualified domain
name as it appears in a zone file.

Characters which are recognised by RFC1035 zone file syntax are
represented by the appropriate escape sequence.

=cut

sub string {
	local $_ = &identifier;
	s/^([\$'";@])/\\$1/;					# escape leading special char
	return /[$dot]$/o ? $_ : $_ . $dot;			# append trailing dot
}


=head2 origin

    $create = origin Net::DNS::Domain( $ORIGIN );
    $result = &$create( sub{ new Net::DNS::RR( 'mx MX 10 a' ); } );
    $expect = new Net::DNS::RR( "mx.$ORIGIN. MX 10 a.$ORIGIN." );

Class method which returns a reference to a subroutine wrapper which
will execute a given constructor in a context within which $ORIGIN is
defined.

=cut

sub origin {
	my $class = shift;
	my $name = shift || '';

	return sub { my $constructor = shift; &$constructor; }	# all names absolute
			unless $name =~ /[^.]/;

	my $domain = new Net::DNS::Domain($name);
	return sub {						# closure w.r.t. $domain
		local $ORIGIN = $domain;			# dynamically scoped $ORIGIN
		my $constructor = shift;
		&$constructor;
			}
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


sub _decode_ascii {

	return ASCII->decode(shift) if ASCII;

	# partial transliteration for single octet character encodings
	local $_ = shift;

	tr
	[\055\041-\054\056-\176\000-\377]
	[-!"#$%&'()*+,./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~]d
			unless ASCII;
	return $_;						# native 8-bit code
}


sub _encode_ascii {

	return Net::LibIDN::idn_to_ascii( shift, 'utf-8' ) || croak 'invalid name'
			if UTF8 && $_[0] =~ /[^\000-\177]/;

	return ASCII->encode(shift) if ASCII;

	# partial transliteration for single octet character encodings
	local $_ = shift;

	tr
	[-!"#$%&'()*+,./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~\000-\377]
	[\055\041-\054\056-\176]d
			unless ASCII;
	return $_;						# ASCII
}


my %escape = eval {				## precalculated ASCII escape table
	my %table;

	foreach ( 0 .. 127 ) {					# ASCII
		my $char = pack 'C', $_;
		$table{$char} = $char;
	}

	# minimal character escapes
	foreach ( 46, 92 ) {					# \. \\
		my $char = pack 'C', $_;
		$table{$char} = pack 'C*', 92, $_;
	}

	foreach ( 0 .. 32, 127 .. 255 ) {			# \ddd
		my $char = pack 'C', $_;
		$table{$char} = sprintf '\\%03u', $_;
	}

	return %table;
};


sub _escape {				## Insert escape sequences in string
	local $_ = shift;
	s/([^\055\101-\132\141-\172\060-\071])/$escape{$1}/eg;
	return $_;
}


my %unescape = eval {				## precalculated numeric escape table
	my %table;

	foreach ( 0 .. 255 ) {
		my $aseq = _encode_ascii sprintf( '%03u', $_ );
		$table{$aseq} = pack 'C', $_;
		$table{$aseq} = pack 'Ca*', $_, _encode_ascii '666' if $_ == 92;
	}

	return %table;
};


sub _unescape {				## Remove escape sequences in string
	local $_ = shift;

	while (/\134([\060-\062][\060-\071]{2})/) {		# numeric escape
		s/\134($1)/$unescape{$1}/eg;
	}

	s/\134\066\066\066/\134\134/g;				# reveal escaped escape
	s/\134(.)/$1/g;						# character escape
	return $_;
}


1;
__END__


########################################

=head1 BUGS

Coding strategy is intended to avoid creating unnecessary argument
lists and stack frames. This improves efficiency at the expense of
code readability.

Platform specific character coding features are conditionally
compiled into the code.


=head1 COPYRIGHT

Copyright (c)2009-2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::LibIDN>, L<Net::DNS>, RFC1034, RFC1035, RFC5891,
Unicode Technical Report #16

=cut

