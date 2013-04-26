package Net::DNS::Text;

#
# $Id: Text.pm 965 2011-12-02 22:04:30Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 965 $)[1];


=head1 NAME

Net::DNS::Text - Domain Name System text representation

=head1 SYNOPSIS

    use Net::DNS::Text;

    $object = new Net::DNS::Text('example');
    $string = $object->string;

    $object = decode Net::DNS::Text( \$data, $offset );
    ( $object, $next ) = decode Net::DNS::Text( \$data, $offset );

    $data = $object->encode;
    $text = $object->value;

=head1 DESCRIPTION

The C<Net::DNS::Text> module implements a class of text objects
with associated class and instance methods.

Each text object instance has a fixed identity throughout its
lifetime.

=cut


use strict;
use integer;
use Carp;


use constant ASCII => eval {
	require Encode;
	Encode::find_encoding('ASCII');				# return encoding object
} || 0;

use constant UTF8 => eval {
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 §3.6]
	Encode::find_encoding('UTF8');				# return encoding object
} || 0;


=head1 METHODS

=head2 new

    $object = new Net::DNS::Text('example');

Creates a text object which encapsulates a single character
string component of a resource record.

Arbitrary single-byte characters can be represented by \ followed
by exactly three decimal digits. Such characters are devoid of
any special meaning.

A character preceded by \ represents itself, without any special
interpretation.

=cut

my %unescape;				## precalculated numeric escape table

sub new {
	my $self = bless [], shift;
	croak 'argument undefined' unless defined $_[0];

	local $_ = &_encode_utf8;

	s/^([\042\047])(.*)\1$/$2/;				# strip quotes

	s/\134\134/\134\066\066\066/g;				# disguise escaped escape

	while (/\134([\060-\062][\060-\071]{2})/) {		# numeric escape
		s/\134($1)/$unescape{$1}/eg;
	}

	s/\134\066\066\066/\134\134/g;				# reveal escaped escape
	s/\134(.)/$1/g;						# character escape

	while ( length $_ > 255 ) {
		my $chunk = substr( $_, 0, 255 );		# carve into chunks
		substr( $chunk, -length($1) ) = '' if $chunk =~ /.([\300-\377][\200-\277]+)$/;
		push @$self, $chunk;
		substr( $_, 0, length $chunk ) = '';
	}
	push @$self, $_;

	return $self;
}


=head2 decode

    $object = decode Net::DNS::Text( \$buffer, $offset );

    ( $object, $next ) = decode Net::DNS::Text( \$buffer, $offset );

Creates a text object which represents the decoded data at the
indicated offset within the data buffer.

The argument list consists of a reference to a scalar containing
the wire-format data and offset of the text data.

The returned offset value indicates the start of the next item in
the data buffer.

=cut

sub decode {
	my $self   = bless [], shift;
	my $buffer = shift;					# reference to data buffer
	my $offset = shift || 0;				# offset within buffer

	my $size = unpack "\@$offset C", $$buffer;
	my $next = ++$offset + $size;
	croak 'corrupt wire-format data' if $next > length $$buffer;

	push @$self, unpack "\@$offset a$size", $$buffer;

	return wantarray ? ( $self, $next ) : $self;
}


=head2 encode

    $data = $object->encode;

Returns the wire-format encoded representation of the text object
suitable for inclusion in a DNS packet buffer.

=cut

sub encode {
	my $self = shift;
	join '', map { pack 'C a*', length $_, $_ } @$self;
}


=head2 value

    $value = $text->value;

Returns the character representation of the text object.

=cut

sub value {
	my $self = shift;
	_decode_utf8( join '', @$self );
}


=head2 string

    $string = $text->string;

Returns the escaped string representation of the text object.

=cut

my %escape;							# precalculated ASCII/UTF-8 escape table
my $QQ = _decode_utf8( pack 'C', 34 );

sub string {
	my $self = shift;

	local $_ = join '', @$self;
	s/([^\040\060-\132\141-\172])/$escape{$1}/eg;		# escape special and unprintable

	$_ = _decode_utf8($_);

	# Note: Script-specific rules determine which Unicode characters match \s
	return $_ unless /^$|\s|["\$'():;@`]/;			# unquoted contiguous

	return join '', $QQ, $_, $QQ;				# quoted string
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


sub _decode_utf8 {

	return UTF8->decode(shift) if UTF8;

	return ASCII->decode(shift) if ASCII && not UTF8;

	# partial transliteration for single octet character encodings
	local $_ = shift;

	tr
	[\055\011\040-\054\056-\176\302-\364\000-\377]
	[-	 !"#$%&'()*+,./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~???????????????????????????????????????????????????]d
			unless ASCII;
	return $_;						# native 8-bit code
}


sub _encode_utf8 {

	return UTF8->encode(shift) if UTF8;

	return ASCII->encode(shift) if ASCII && not UTF8;

	# partial transliteration for single octet character encodings
	local $_ = shift;

	tr
	[-	 !"#$%&'()*+,./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~\000-\377]
	[\055\011\040-\054\056-\176]d
			unless ASCII;
	return $_;						# ASCII
}


%escape = eval {				## precalculated ASCII/UTF-8 escape table
	my %table;
	my @C0 = ( 0 .. 8, 10 .. 31 );				# except tab character
	my @NA = UTF8 ? () : ( 128 .. 255 );

	foreach ( 0 .. 255 ) {					# transparent
		my $char = pack 'C', $_;
		$table{$char} = $char;
	}

	# minimal character escapes
	foreach ( 34, 92 ) {					# \" \\
		my $char = pack 'C', $_;
		$table{$char} = pack 'C*', 92, $_;
	}

	foreach ( @C0, 127, @NA ) {				# \ddd
		my $char = pack 'C', $_;
		$table{$char} = sprintf '\\%03u', $_;
	}

	return %table;
};


%unescape = eval {				## precalculated numeric escape table
	my %table;

	foreach ( 0 .. 255 ) {
		my $aseq = _encode_utf8 sprintf( '%03u', $_ );
		$table{$aseq} = pack 'C', $_;
		$table{$aseq} = pack 'Ca*', $_, _encode_utf8 '666' if $_ == 92;
	}

	return %table;
};


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

L<perl>, L<Net::DNS>, RFC1035, RFC3629,
Unicode Technical Report #16

=cut

