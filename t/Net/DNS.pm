package Net::DNS;

#
# $Id: DNS.pm 981 2012-01-27 23:01:31Z willem $
#
use vars qw($SVNVERSION $VERSION);
BEGIN {
	$SVNVERSION = (qw$LastChangedRevision: 981 $)[1];
	$VERSION = '0.68';
}


=head1 NAME

Net::DNS - Perl interface to the Domain Name System

=head1 SYNOPSIS

    use Net::DNS;

=head1 DESCRIPTION

Net::DNS is a collection of Perl modules that act as a Domain
Name System (DNS) resolver.  It allows the programmer to perform
DNS queries that are beyond the capabilities of C<gethostbyname>
and C<gethostbyaddr>.

The programmer should be somewhat familiar with the format of
a DNS packet and its various sections.  See RFC 1035 or
I<DNS and BIND> (Albitz & Liu) for details.

=cut





use vars qw(
    $HAVE_XS
    $DNSSEC
    $DN_EXPAND_ESCAPES
    @ISA
    @EXPORT
    @EXPORT_OK
    %typesbyname
    %typesbyval
    %qtypesbyname
    %qtypesbyval
    %metatypesbyname
    %metatypesbyval
    %classesbyname
    %classesbyval
    %opcodesbyname
    %opcodesbyval
    %rcodesbyname
    %rcodesbyval
);



BEGIN {

    require Exporter;
    @ISA     = qw(Exporter );
    # these need to live here because of dependencies further on.
    @EXPORT = qw(mx yxrrset nxrrset yxdomain nxdomain rr_add rr_del SEQUENTIAL UNIXTIME YYYYMMDDxx);
    @EXPORT_OK= qw(name2labels wire2presentation rrsort stripdot);

    # XXX gdnsd local mod: don't even check for XS and DNSSEC
    $HAVE_XS = 0;
    $DNSSEC = 0;
}


use strict;
use Carp;
use Net::DNS::Resolver;
use Net::DNS::Packet;
#use Net::DNS::Update; # XXX gdnsd local mod: don't need it
use Net::DNS::Header;
use Net::DNS::Question;
use Net::DNS::RR;   # use only after $Net::DNS::DNSSEC has been evaluated



#
# If you implement an RR record make sure you also add it to
# %Net::DNS::RR::RR hash otherwise it will be treated as unknown type.
#
# See http://www.iana.org/assignments/dns-parameters for assignments and references.

# Do not use these tybesby hashes directly. Use the interface
# functions, see below.

%typesbyname = (
    'SIGZERO'   => 0,       # RFC2931 consider this a pseudo type
    'A'         => 1,       # RFC 1035, Section 3.4.1
    'NS'        => 2,       # RFC 1035, Section 3.3.11
    'MD'        => 3,       # RFC 1035, Section 3.3.4 (obsolete)		NOT IMPLEMENTED
    'MF'        => 4,       # RFC 1035, Section 3.3.5 (obsolete)		NOT IMPLEMENTED
    'CNAME'     => 5,       # RFC 1035, Section 3.3.1
    'SOA'       => 6,       # RFC 1035, Section 3.3.13
    'MB'        => 7,       # RFC 1035, Section 3.3.3
    'MG'        => 8,       # RFC 1035, Section 3.3.6
    'MR'        => 9,       # RFC 1035, Section 3.3.8
    'NULL'      => 10,      # RFC 1035, Section 3.3.10
    'WKS'       => 11,      # RFC 1035, Section 3.4.2 (deprecated)		NOT IMPLEMENTED
    'PTR'       => 12,      # RFC 1035, Section 3.3.12
    'HINFO'     => 13,      # RFC 1035, Section 3.3.2
    'MINFO'     => 14,      # RFC 1035, Section 3.3.7
    'MX'        => 15,      # RFC 1035, Section 3.3.9
    'TXT'       => 16,      # RFC 1035, Section 3.3.14
    'RP'        => 17,      # RFC 1183, Section 2.2
    'AFSDB'     => 18,      # RFC 1183, Section 1
    'X25'       => 19,      # RFC 1183, Section 3.1
    'ISDN'      => 20,      # RFC 1183, Section 3.2
    'RT'        => 21,      # RFC 1183, Section 3.3
    'NSAP'      => 22,      # RFC 1706, Section 5
    'NSAP_PTR'  => 23,      # RFC 1348 (obsolete by RFC 1637)			NOT IMPLEMENTED
    'SIG'       => 24,      # RFC 2535, Section 4.1				impemented in Net::DNS::SEC
    'KEY'       => 25,      # RFC 2535, Section 3.1				impemented in Net::DNS::SEC
    'PX'        => 26,      # RFC 2163,
    'GPOS'      => 27,      # RFC 1712 (obsolete ?)				NOT IMPLEMENTED
    'AAAA'      => 28,      # RFC 1886, Section 2.1
    'LOC'       => 29,      # RFC 1876
    'NXT'       => 30,      # RFC 2535, Section 5.2 obsoleted by RFC3755	impemented in Net::DNS::SEC
    'EID'       => 31,      # draft-ietf-nimrod-dns-xx.txt
    'NIMLOC'    => 32,      # draft-ietf-nimrod-dns-xx.txt
    'SRV'       => 33,      # RFC 2052
    'ATMA'      => 34,      # non-standard    					NOT IMPLEMENTED
    'NAPTR'     => 35,      # RFC 2168
    'KX'        => 36,      # RFC 2230
    'CERT'      => 37,      # RFC 2538
    'A6'        => 38,      # RFC3226, RFC2874. See RFC 3363 made A6 exp.	NOT IMPLEMENTED
    'DNAME'     => 39,      # RFC 2672
    'SINK'      => 40,      # non-standard					NOT IMPLEMENTED
    'OPT'       => 41,      # RFC 2671
    'APL'       => 42,      # RFC 3123
    'DS'        => 43,      # RFC 4034  					implemented in Net::DNS::SEC
    'SSHFP'     => 44,      # RFC 4255
    'IPSECKEY'  => 45,      # RFC 4025
    'RRSIG'     => 46,      # RFC 4034 						implemented in Net::DNS::SEC
    'NSEC'      => 47,      # RFC 4034						implemented in Net::DNS::SEC
    'DNSKEY'    => 48,      # RFC 4034						inplemented in Net::DNS::SEC
    'DHCID'     => 49,      # RFC4701
    'NSEC3'     => 50,      # RFC5155
    'NSEC3PARAM' => 51,     # RFC5155
# 52-54 are unassigned
    'HIP'       => 55,      # RFC5205
    'NINFO'     => 56,      # non-standard					NOT IMPLEMENTED
    'RKEY'      => 57,      # non-standard					NOT IMPLEMENTED
# 58-98 are unasigned
    'SPF'       => 99,      # RFC 4408
    'UINFO'     => 100,     # non-standard
    'UID'       => 101,     # non-standard
    'GID'       => 102,     # non-standard
    'UNSPEC'    => 103,     # non-standard
# 104-248 are unasigned
    'TKEY'      => 249,     # RFC 2930
    'TSIG'      => 250,     # RFC 2931
    'IXFR'      => 251,     # RFC 1995
    'AXFR'      => 252,     # RFC 1035
    'MAILB'     => 253,     # RFC 1035 (MB, MG, MR)
    'MAILA'     => 254,     # RFC 1035 (obsolete - see MX)
    'ANY'       => 255,     # RFC 1035
    'TA'        => 32768,    # non-standard					NOT IMPLEMENTED
    'DLV'       => 32769    # RFC 4431						implemented in Net::DNS::SEC
);
%typesbyval = reverse %typesbyname;


#
# typesbyval and typesbyname functions are wrappers around the similarly named
# hashes. They are used for 'unknown' DNS RR types (RFC3597)

# typesbyname returns they TYPEcode as a function of the TYPE
# mnemonic. If the TYPE mapping is not specified the generic mnemonic
# TYPE### is returned.


# typesbyval returns they TYPE mnemonic as a function of the TYPE
# code. If the TYPE mapping is not specified the generic mnemonic
# TYPE### is returned.
#

sub typesbyname {
    my $name = uc shift;

    return $typesbyname{$name} if defined $typesbyname{$name};

    confess "unknown type $name" unless $name =~ m/TYPE(\d+)/o;

    my $val = 0 + $1;
    confess 'argument out of range' if $val > 0xffff;

    return $val ? $val : '00';    ## preserve historical behaviour for TYPE0 ##
}

sub typesbyval {
    my $val = shift;

    return $typesbyval{$val} if defined $typesbyval{$val};

    $val += 0;
    confess 'argument out of range' if $val > 0xffff;

    return "TYPE$val";
}



#
# Do not use these classesby hashes directly. See below.
#

%classesbyname = (
    'IN'        => 1,       # RFC 1035
    'CH'        => 3,       # RFC 1035
    'HS'        => 4,       # RFC 1035
    'NONE'      => 254,     # RFC 2136
    'ANY'       => 255,     # RFC 1035
);
%classesbyval = reverse %classesbyname;



# classesbyval and classesbyname functions are wrappers around the
# similarly named hashes. They are used for 'unknown' DNS RR classess
# (RFC3597)

# See typesbyval and typesbyname, these beasts have the same functionality

sub classesbyname {
    my $name = uc shift;

    return $classesbyname{$name} if defined $classesbyname{$name};

    confess "unknown class $name" unless $name =~ m/CLASS(\d+)/o;

    my $val = 0 + $1;
    confess 'argument out of range' if $val > 0xffff;

    return $val;
}

sub classesbyval {
    my $val = shift;

    return $classesbyval{$val} if defined $classesbyval{$val};

    $val += 0;
    confess 'argument out of range' if $val > 0xffff;

    return "CLASS$val";
}



# The qtypesbyval and metatypesbyval specify special typecodes
# See rfc2929 and the relevant IANA registry
# http://www.iana.org/assignments/dns-parameters


%qtypesbyname = (
    'IXFR'   => 251,  # incremental transfer                [RFC1995]
    'AXFR'   => 252,  # transfer of an entire zone          [RFC1035]
    'MAILB'  => 253,  # mailbox-related RRs (MB, MG or MR)   [RFC1035]
    'MAILA'  => 254,  # mail agent RRs (Obsolete - see MX)   [RFC1035]
    'ANY'    => 255,  # all records                      [RFC1035]
);
%qtypesbyval = reverse %qtypesbyname;


%metatypesbyname = (
    'TKEY'        => 249,    # Transaction Key   [RFC2930]
    'TSIG'        => 250,    # Transaction Signature  [RFC2845]
    'OPT'         => 41,     # RFC 2671
);
%metatypesbyval = reverse %metatypesbyname;


%opcodesbyname = (
    'QUERY'        => 0,        # RFC 1035
    'IQUERY'       => 1,        # RFC 1035
    'STATUS'       => 2,        # RFC 1035
    'NS_NOTIFY_OP' => 4,        # RFC 1996
    'UPDATE'       => 5,        # RFC 2136
);
%opcodesbyval = reverse %opcodesbyname;


%rcodesbyname = (
    'NOERROR'   => 0,       # RFC 1035
    'FORMERR'   => 1,       # RFC 1035
    'SERVFAIL'  => 2,       # RFC 1035
    'NXDOMAIN'  => 3,       # RFC 1035
    'NOTIMP'    => 4,       # RFC 1035
    'REFUSED'   => 5,       # RFC 1035
    'YXDOMAIN'  => 6,       # RFC 2136
    'YXRRSET'   => 7,       # RFC 2136
    'NXRRSET'   => 8,       # RFC 2136
    'NOTAUTH'   => 9,       # RFC 2136
    'NOTZONE'   => 10,      # RFC 2136
);
%rcodesbyval = reverse %rcodesbyname;


sub version      { $VERSION; }
sub PACKETSZ  () { 512; }
sub HFIXEDSZ  () {  12; }
sub QFIXEDSZ  () {   4; }
sub RRFIXEDSZ () {  10; }
sub INT32SZ   () {   4; }
sub INT16SZ   () {   2; }



# mx()
#
# Usage:
#    my @mxes = mx('example.com', 'IN');
#
sub mx {
    my $res = ref $_[0] ? shift : Net::DNS::Resolver->new;

    my ($name, $class) = @_;
    $class ||= 'IN';

    my $ans = $res->query($name, 'MX', $class) || return;

    # This construct is best read backwords.
    #
    # First we take the answer secion of the packet.
    # Then we take just the MX records from that list
    # Then we sort the list by preference
    # Then we return it.
    # We do this into an array to force list context.
    my @ret = sort { $a->preference <=> $b->preference }
              grep { $_->type eq 'MX'} $ans->answer;


    return @ret;
}


#
# Auxiliary functions to support dynamic update.
#

sub yxrrset { return new Net::DNS::RR( shift, 'yxrrset' ); }

sub nxrrset { return new Net::DNS::RR( shift, 'nxrrset' ); }

sub yxdomain { return new Net::DNS::RR( shift, 'yxdomain' ); }

sub nxdomain { return new Net::DNS::RR( shift, 'nxdomain' ); }

sub rr_add { return new Net::DNS::RR( shift, 'rr_add' ); }

sub rr_del { return new Net::DNS::RR( shift, 'rr_del' ); }



# Utility function
#
# name2labels to translate names from presentation format into an
# array of "wire-format" labels.


# in: $dname a string with a domain name in presentation format (1035
# sect 5.1)
# out: an array of labels in wire format.


sub name2labels {
    my $dname=shift;
    my @names;
    my $j=0;
    while ($dname){
	($names[$j],$dname)=presentation2wire($dname);
	$j++;
    }

    return @names;
}




sub wire2presentation {
    my  $wire=shift;
    my  $presentation="";
    my $length=length($wire);
    # There must be a nice regexp to do this.. but since I failed to
    # find one I scan the name string until I find a '\', at that time
    # I start looking forward and do the magic.

    my $i=0;

    while ($i < $length ){
	my $char=unpack("x".$i."C1",$wire);
	if ( $char < 33 || $char > 126 ){
	    $presentation.= sprintf ("\\%03u" ,$char);
	}elsif ( $char == ord( "\"" )) {
	    $presentation.= "\\\"";
	}elsif ( $char == ord( "\$" )) {
	    $presentation.= "\\\$";
	}elsif ( $char == ord( "(" )) {
	    $presentation.= "\\(";
	}elsif ( $char == ord( ")" )) {
	    $presentation.= "\\)";
	}elsif ( $char == ord( ";" )) {
	    $presentation.= "\\;";
	}elsif ( $char == ord( "@" )) {
	    $presentation.= "\\@";
	}elsif ( $char == ord( "\\" )) {
	    $presentation.= "\\\\" ;
	}elsif ( $char==ord (".") ){
	    $presentation.= "\\." ;
	}else{
	    $presentation.=chr($char) 	;
	}
	$i++;
    }

    return $presentation;

}




sub stripdot {
	# Code courtesy of JMEHNLE <JMEHNLE@cpan.org>
	# rt.cpan.org #51009

	# Strips the final non-escaped dot from a domain name.  Note
	# that one could have a label that looks like "foo\\\\\.\.."
	# although not likely one wants to deal with that cracefully.
	# This utilizes 2 functions in the DNS module to deal with
	# thing cracefully.

	return join('.', map(wire2presentation($_), name2labels(shift)));

}



# ($wire,$leftover)=presentation2wire($leftover);

# Will parse the input presentation format and return everything before
# the first non-escaped "." in the first element of the return array and
# all that has not been parsed yet in the 2nd argument.


sub presentation2wire {
    my  $presentation=shift;
    my  $wire="";

    while ($presentation =~ /\G([^.\\]*)([.\\]?)/g){
        $wire .= $1 if defined $1;

        if ($2) {
            if ($2 eq '.') {
                return ($wire,substr($presentation,pos $presentation));
	    }

            #backslash found
            if ($presentation =~ /\G(\d\d\d)/gc) {
                $wire.=pack("C",$1);
            } elsif ($presentation =~ /\G([@().\\])/gc){
                $wire .= $1;
            }
        }
    }

    return $wire;
}




#
# Auxiliary functions to support policy-driven zone serial numbering.
#
#	$successor = $soa->serial(SEQUENTIAL);
#	$successor = $soa->serial(UNIXTIME);
#	$successor = $soa->serial(YYYYMMDDxx);
#

sub SEQUENTIAL { undef }

sub UNIXTIME { return CORE::time; }

sub YYYYMMDDxx {
	my ( $dd, $mm, $yy ) = ( localtime )[3 .. 5];
	return 1900010000 + sprintf '%d%0.2d%0.2d00', $yy, $mm, $dd;
}



sub rrsort {
    my ($rrtype,$attribute,@rr_array)=@_;
    unless (exists($Net::DNS::typesbyname{uc($rrtype)})){
	# unvalid error type
	return();
    }
    unless (defined($attribute)){
	# no second argument... hence no array.
	return();
    }

    # attribute is empty or not specified.

    if( ref($attribute)=~/^Net::DNS::RR::.*/){
	# push the attribute back on the array.
	push @rr_array,$attribute;
	undef($attribute);

    }

    my @extracted_rr;
    foreach my $rr (@rr_array){
	push( @extracted_rr, $rr )if (uc($rr->type) eq uc($rrtype));
    }
    return () unless  @extracted_rr;
    my $func=("Net::DNS::RR::".$rrtype)->get_rrsort_func($attribute);
    my @sorted=sort $func  @extracted_rr;
    return @sorted;

}









1;
__END__



=head2 Resolver Objects

A resolver object is an instance of the
L<Net::DNS::Resolver|Net::DNS::Resolver> class. A program can have
multiple resolver objects, each maintaining its own state information
such as the nameservers to be queried, whether recursion is desired,
etc.

=head2 Packet Objects

L<Net::DNS::Resolver|Net::DNS::Resolver> queries return
L<Net::DNS::Packet|Net::DNS::Packet> objects.  Packet objects have five
sections:

=over 3

=item *

The header section, a L<Net::DNS::Header|Net::DNS::Header> object.

=item *

The question section, a list of L<Net::DNS::Question|Net::DNS::Question>
objects.

=item *

The answer section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=item *

The authority section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=item *

The additional section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=back

=head2 Update Objects

The L<Net::DNS::Update|Net::DNS::Update> package is a subclass of
L<Net::DNS::Packet|Net::DNS::Packet> for creating packet objects to be
used in dynamic updates.

=head2 Header Objects

L<Net::DNS::Header|Net::DNS::Header> objects represent the header
section of a DNS packet.

=head2 Question Objects

L<Net::DNS::Question|Net::DNS::Question> objects represent the question
section of a DNS packet.

=head2 RR Objects

L<Net::DNS::RR|Net::DNS::RR> is the base class for DNS resource record
(RR) objects in the answer, authority, and additional sections of a DNS
packet.

Don't assume that RR objects will be of the type you requested -- always
check an RR object's type before calling any of its methods.

=head1 METHODS

See the manual pages listed above for other class-specific methods.

=head2 version

    print Net::DNS->version, "\n";

Returns the version of Net::DNS.

=head2 mx

    # Use a default resolver -- can't get an error string this way.
    use Net::DNS;
    my @mx = mx("example.com");

    # Use your own resolver object.
    use Net::DNS;
    my $res = Net::DNS::Resolver->new;
    my  @mx = mx($res, "example.com");

Returns a list of L<Net::DNS::RR::MX|Net::DNS::RR::MX> objects
representing the MX records for the specified name; the list will be
sorted by preference. Returns an empty list if the query failed or no MX
records were found.

This method does not look up A records -- it only performs MX queries.

See L</EXAMPLES> for a more complete example.

=head2 yxrrset

Use this method to add an "RRset exists" prerequisite to a dynamic
update packet.  There are two forms, value-independent and
value-dependent:

    # RRset exists (value-independent)
    $update->push(pre => yxrrset("host.example.com A"));

Meaning:  At least one RR with the specified name and type must
exist.

    # RRset exists (value-dependent)
    $packet->push(pre => yxrrset("host.example.com A 10.1.2.3"));

Meaning:  At least one RR with the specified name and type must
exist and must have matching data.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 nxrrset

Use this method to add an "RRset does not exist" prerequisite to
a dynamic update packet.

    $packet->push(pre => nxrrset("host.example.com A"));

Meaning:  No RRs with the specified name and type can exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 yxdomain

Use this method to add a "name is in use" prerequisite to a dynamic
update packet.

    $packet->push(pre => yxdomain("host.example.com"));

Meaning:  At least one RR with the specified name must exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 nxdomain

Use this method to add a "name is not in use" prerequisite to a
dynamic update packet.

    $packet->push(pre => nxdomain("host.example.com"));

Meaning:  No RR with the specified name can exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 rr_add

Use this method to add RRs to a zone.

    $packet->push(update => rr_add("host.example.com A 10.1.2.3"));

Meaning:  Add this RR to the zone.

RR objects created by this method should be added to the "update"
section of a dynamic update packet.  The TTL defaults to 86400
seconds (24 hours) if not specified.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 rr_del

Use this method to delete RRs from a zone.  There are three forms:
delete an RRset, delete all RRsets, and delete an RR.

    # Delete an RRset.
    $packet->push(update => rr_del("host.example.com A"));

Meaning:  Delete all RRs having the specified name and type.

    # Delete all RRsets.
    $packet->push(update => rr_del("host.example.com"));

Meaning:  Delete all RRs having the specified name.

    # Delete an RR.
    $packet->push(update => rr_del("host.example.com A 10.1.2.3"));

Meaning:  Delete all RRs having the specified name, type, and data.

RR objects created by this method should be added to the "update"
section of a dynamic update packet.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.



=head1 Zone Serial Number Management

The Net::DNS module provides auxiliary functions which support
policy-driven zone serial numbering regimes.

=head2 Strictly Sequential

    $successor = $soa->serial( SEQUENTIAL );

The existing serial number is incremented modulo 2**32.

=head2 Time Encoded

    $successor = $soa->serial( UNIXTIME );

The Unix time scale will be used as the basis for zone serial
numbering. The serial number will be incremented if the time
elapsed since the previous update is less than one second.

=head2 Date Encoded

    $successor = $soa->serial( YYYYMMDDxx );

The 32 bit value returned by the auxiliary YYYYMMDDxx() function
will be used as the base for the date-coded zone serial number.
Serial number increments must be limited to 100 per day for the
date information to remain useful.



=head2 Sorting of RR arrays

As of version 0.55 there is functionality to help you sort RR
arrays. 'rrsort()' is the function that is available to do the
sorting. In most cases rrsort will give you the answer that you
want but you can specify your own sorting method by using the
Net::DNS::RR::FOO->set_rrsort_func() class method. See L<Net::DNS::RR>
for details.

=head3 rrsort()

   use Net::DNS qw(rrsort);

   my @prioritysorted=rrsort("SRV","priority",@rr_array);


rrsort() selects all RRs from the input array that are of the type
that are defined in the first argument. Those RRs are sorted based on
the attribute that is specified as second argument.

There are a number of RRs for which the sorting function is
specifically defined for certain attributes.  If such sorting function
is defined in the code (it can be set or overwritten using the
set_rrsort_func() class method) that function is used.

For instance:
   my @prioritysorted=rrsort("SRV","priority",@rr_array);
returns the SRV records sorted from lowest to heighest priority and
for equal priorities from heighes to lowes weight.

If the function does not exist then a numerical sort on the attribute
value is performed.
   my @portsorted=rrsort("SRV","port",@rr_array);

If the attribute does not exist for a certain RR than the RRs are
sorted on string comparrisson of the rdata.

If the attribute is not defined than either the default_sort function
will be defined or "Canonical sorting" (as defined by DNSSEC) will be
used.

rrsort() returns a sorted array with only elements of the specified
RR type or undef.

rrsort() returns undef when arguments are incorrect.



=head1 EXAMPLES

The following examples show how to use the C<Net::DNS> modules.
See the other manual pages and the demo scripts included with the
source code for additional examples.

See the C<Net::DNS::Update> manual page for an example of performing
dynamic updates.

=head2 Look up a host's addresses.

  use Net::DNS;
  my $res   = Net::DNS::Resolver->new;
  my $query = $res->search("host.example.com");

  if ($query) {
      foreach my $rr ($query->answer) {
          next unless $rr->type eq "A";
          print $rr->address, "\n";
      }
  } else {
      warn "query failed: ", $res->errorstring, "\n";
  }

=head2 Find the nameservers for a domain.

  use Net::DNS;
  my $res   = Net::DNS::Resolver->new;
  my $query = $res->query("example.com", "NS");

  if ($query) {
      foreach $rr (grep { $_->type eq 'NS' } $query->answer) {
          print $rr->nsdname, "\n";
      }
  }
  else {
      warn "query failed: ", $res->errorstring, "\n";
  }

=head2 Find the MX records for a domain.

  use Net::DNS;
  my $name = "example.com";
  my $res  = Net::DNS::Resolver->new;
  my @mx   = mx($res, $name);

  if (@mx) {
      foreach $rr (@mx) {
          print $rr->preference, " ", $rr->exchange, "\n";
      }
  } else {
      warn "Can't find MX records for $name: ", $res->errorstring, "\n";
  }


=head2 Print a domain's SOA record in zone file format.

  use Net::DNS;
  my $res   = Net::DNS::Resolver->new;
  my $query = $res->query("example.com", "SOA");

  if ($query) {
      ($query->answer)[0]->print;
  } else {
      print "query failed: ", $res->errorstring, "\n";
  }

=head2 Perform a zone transfer and print all the records.

  use Net::DNS;
  my $res  = Net::DNS::Resolver->new;
  $res->nameservers("ns.example.com");

  my @zone = $res->axfr("example.com");

  foreach $rr (@zone) {
      $rr->print;
  }

=head2 Perform a background query and do some other work while waiting
for the answer.

  use Net::DNS;
  my $res    = Net::DNS::Resolver->new;
  my $socket = $res->bgsend("host.example.com");

  until ($res->bgisready($socket)) {
      # do some work here while waiting for the answer
      # ...and some more here
  }

  my $packet = $res->bgread($socket);
  $packet->print;


=head2 Send a background query and use select to determine when the answer
has arrived.

  use Net::DNS;
  use IO::Select;

  my $timeout = 5;
  my $res     = Net::DNS::Resolver->new;
  my $bgsock  = $res->bgsend("host.example.com");
  my $sel     = IO::Select->new($bgsock);

  # Add more sockets to $sel if desired.
  my @ready = $sel->can_read($timeout);
  if (@ready) {
      foreach my $sock (@ready) {
          if ($sock == $bgsock) {
              my $packet = $res->bgread($bgsock);
              $packet->print;
              $bgsock = undef;
          }
          # Check for the other sockets.
          $sel->remove($sock);
          $sock = undef;
      }
  } else {
      warn "timed out after $timeout seconds\n";
  }


=head1 BUGS

C<Net::DNS> is slow.

For other items to be fixed, or if you discover a bug in this
distribution please use the CPAN bug reporting system.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr.
Portions Copyright(c)2002-2004 Chris Reinhardt.
Portions Copyright(c)2005 Olaf Kolkman (RIPE NCC)
Portions Copyright(c)2006 Olaf Kolkman (NLnet Labs)

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 AUTHOR INFORMATION

Net::DNS is currently maintained at NLnet Labs (www.nlnetlabs.nl) by:
        Olaf Kolkman
	olaf@net-dns.org

Between 2002 and 2004 Net::DNS was maintained by:
       Chris Reinhardt


Net::DNS was created by:
	Michael Fuhr
	mike@fuhr.org



For more information see:
    http://www.net-dns.org/

Stay tuned and syndicate:
    http://www.net-dns.org/blog/

=head1 SEE ALSO

L<perl>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>, L<Net::DNS::Update>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>, RFC 1035,
I<DNS and BIND> by Paul Albitz & Cricket Liu

=cut

