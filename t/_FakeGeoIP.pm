package _FakeGeoIP;

use strict;
use warnings;
use integer;

# This code generates a custom binary GeoIP database, in the standard
#  MaxMind IPv4 Country format.  The intended purpose is to create small,
#  fake databases for test suites for GeoIP-related software.
# Input is text data on STDIN, output filename is the only argument.

# Text input format:
#   Lines are of the form:
#     192.0.2.1/24 => US
#   Leading/trailing/excess whitespace is ok
#   Blank lines are ok
#   Comments with '#' are ok

# Text input data rules:
#   Your input must cover the entire IPv4 address space.
#   You cannot have the singleton data 0.0.0.0/0, at a minimum
#     you must define 0.0.0.0/1 and 128.0.0.0/1.
#   Your input must be pre-sorted into ascending network order.
#   The country codes must be legal ones from MaxMind's country
#    code table, which is iso3166-1 2-letter, plus a few custom addons.

# Binary output format (simplified MaxMind IPv4 Country only):
#  The database is effectively a binary tree of IPv4 networks, covering
#    the entire IPv4 address space starting at 0.0.0.0/0
#  Every record in the file is 6 bytes long.
#  A record contains two 24-bit offset numbers
#  The first offset is for the zero-branch, the second for the one-branch.
#  If the offset is < COUNTRY_BEGIN, offset*6 is the byte-offset of
#    the record pointed to by this branch.
#  Otherwise, offset - COUNTRY_BEGIN is the country code for the terminal
#    network at this point, and branch_depth is the netmask for it.
#  COUNTRY_BEGIN is the magic value 16776960.  Given the maximum offset
#    value of 2^24-1, this leaves country codes of the range 0-255, but
#    MaxMind's country lookup table only has legal countries for the
#    range 0-252, the last three being illegal/unused at this time.
#  Data is terminated by 3 bytes of 0xFF.

use constant COUNTRY_BEGIN => 16776960;

my %CCODES = (
    "--" => 0,
    "AP" => 1,
    "EU" => 2,
    "AD" => 3,
    "AE" => 4,
    "AF" => 5,
    "AG" => 6,
    "AI" => 7,
    "AL" => 8,
    "AM" => 9,
    "CW" => 10,
    "AO" => 11,
    "AQ" => 12,
    "AR" => 13,
    "AS" => 14,
    "AT" => 15,
    "AU" => 16,
    "AW" => 17,
    "AZ" => 18,
    "BA" => 19,
    "BB" => 20,
    "BD" => 21,
    "BE" => 22,
    "BF" => 23,
    "BG" => 24,
    "BH" => 25,
    "BI" => 26,
    "BJ" => 27,
    "BM" => 28,
    "BN" => 29,
    "BO" => 30,
    "BR" => 31,
    "BS" => 32,
    "BT" => 33,
    "BV" => 34,
    "BW" => 35,
    "BY" => 36,
    "BZ" => 37,
    "CA" => 38,
    "CC" => 39,
    "CD" => 40,
    "CF" => 41,
    "CG" => 42,
    "CH" => 43,
    "CI" => 44,
    "CK" => 45,
    "CL" => 46,
    "CM" => 47,
    "CN" => 48,
    "CO" => 49,
    "CR" => 50,
    "CU" => 51,
    "CV" => 52,
    "CX" => 53,
    "CY" => 54,
    "CZ" => 55,
    "DE" => 56,
    "DJ" => 57,
    "DK" => 58,
    "DM" => 59,
    "DO" => 60,
    "DZ" => 61,
    "EC" => 62,
    "EE" => 63,
    "EG" => 64,
    "EH" => 65,
    "ER" => 66,
    "ES" => 67,
    "ET" => 68,
    "FI" => 69,
    "FJ" => 70,
    "FK" => 71,
    "FM" => 72,
    "FO" => 73,
    "FR" => 74,
    "SX" => 75,
    "GA" => 76,
    "GB" => 77,
    "GD" => 78,
    "GE" => 79,
    "GF" => 80,
    "GH" => 81,
    "GI" => 82,
    "GL" => 83,
    "GM" => 84,
    "GN" => 85,
    "GP" => 86,
    "GQ" => 87,
    "GR" => 88,
    "GS" => 89,
    "GT" => 90,
    "GU" => 91,
    "GW" => 92,
    "GY" => 93,
    "HK" => 94,
    "HM" => 95,
    "HN" => 96,
    "HR" => 97,
    "HT" => 98,
    "HU" => 99,
    "ID" => 100,
    "IE" => 101,
    "IL" => 102,
    "IN" => 103,
    "IO" => 104,
    "IQ" => 105,
    "IR" => 106,
    "IS" => 107,
    "IT" => 108,
    "JM" => 109,
    "JO" => 110,
    "JP" => 111,
    "KE" => 112,
    "KG" => 113,
    "KH" => 114,
    "KI" => 115,
    "KM" => 116,
    "KN" => 117,
    "KP" => 118,
    "KR" => 119,
    "KW" => 120,
    "KY" => 121,
    "KZ" => 122,
    "LA" => 123,
    "LB" => 124,
    "LC" => 125,
    "LI" => 126,
    "LK" => 127,
    "LR" => 128,
    "LS" => 129,
    "LT" => 130,
    "LU" => 131,
    "LV" => 132,
    "LY" => 133,
    "MA" => 134,
    "MC" => 135,
    "MD" => 136,
    "MG" => 137,
    "MH" => 138,
    "MK" => 139,
    "ML" => 140,
    "MM" => 141,
    "MN" => 142,
    "MO" => 143,
    "MP" => 144,
    "MQ" => 145,
    "MR" => 146,
    "MS" => 147,
    "MT" => 148,
    "MU" => 149,
    "MV" => 150,
    "MW" => 151,
    "MX" => 152,
    "MY" => 153,
    "MZ" => 154,
    "NA" => 155,
    "NC" => 156,
    "NE" => 157,
    "NF" => 158,
    "NG" => 159,
    "NI" => 160,
    "NL" => 161,
    "NO" => 162,
    "NP" => 163,
    "NR" => 164,
    "NU" => 165,
    "NZ" => 166,
    "OM" => 167,
    "PA" => 168,
    "PE" => 169,
    "PF" => 170,
    "PG" => 171,
    "PH" => 172,
    "PK" => 173,
    "PL" => 174,
    "PM" => 175,
    "PN" => 176,
    "PR" => 177,
    "PS" => 178,
    "PT" => 179,
    "PW" => 180,
    "PY" => 181,
    "QA" => 182,
    "RE" => 183,
    "RO" => 184,
    "RU" => 185,
    "RW" => 186,
    "SA" => 187,
    "SB" => 188,
    "SC" => 189,
    "SD" => 190,
    "SE" => 191,
    "SG" => 192,
    "SH" => 193,
    "SI" => 194,
    "SJ" => 195,
    "SK" => 196,
    "SL" => 197,
    "SM" => 198,
    "SN" => 199,
    "SO" => 200,
    "SR" => 201,
    "ST" => 202,
    "SV" => 203,
    "SY" => 204,
    "SZ" => 205,
    "TC" => 206,
    "TD" => 207,
    "TF" => 208,
    "TG" => 209,
    "TH" => 210,
    "TJ" => 211,
    "TK" => 212,
    "TM" => 213,
    "TN" => 214,
    "TO" => 215,
    "TL" => 216,
    "TR" => 217,
    "TT" => 218,
    "TV" => 219,
    "TW" => 220,
    "TZ" => 221,
    "UA" => 222,
    "UG" => 223,
    "UM" => 224,
    "US" => 225,
    "UY" => 226,
    "UZ" => 227,
    "VA" => 228,
    "VC" => 229,
    "VE" => 230,
    "VG" => 231,
    "VI" => 232,
    "VN" => 233,
    "VU" => 234,
    "WF" => 235,
    "WS" => 236,
    "YE" => 237,
    "YT" => 238,
    "RS" => 239,
    "ZA" => 240,
    "ZM" => 241,
    "ME" => 242,
    "ZW" => 243,
    "A1" => 244,
    "A2" => 245,
    "O1" => 246,
    "AX" => 247,
    "GG" => 248,
    "IM" => 249,
    "JE" => 250,
    "BL" => 251,
    "MF" => 252,
    "BQ" => 253,
);

my $ipoct = qr/(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])/;

sub _parse_input {
    my $indata = shift;
    my @nets;
    my $last_bcast = -1;
    my $printnet;
    foreach (split(/\n/, $indata)) {
        s/\#.*$//;        # strip comments
        next if m/^\s*$/; # skip now-empty-ish lines
        m{^\s*(($ipoct)\.($ipoct)\.($ipoct)\.($ipoct)/([0-9]+))\s*=>\s*([A-Z0-9-]{2})\s*$}o
            or die "Cannot parse entry '$_', wanted 'ipv4/mask => CC'";
        $printnet = $1;
        my $netnum = ($2 << 24) + ($3 << 16) + ($4 << 8) + $5;
        my $mask = $6;
        my $cc = $7;
        die "Illegal country code '$cc'" if !exists $CCODES{$cc};
        die "Illegal netmask '$mask' for IPv4" if $mask > 32;
        my $hostmask = ((1 << (32 - $mask)) - 1);
        die "Network '$printnet' illegal (has bits below mask)" if $netnum & $hostmask;
        die "You skipped part of the address space, just before '$printnet'" if ($netnum - 1) > $last_bcast;
        die "'$printnet' invades the space of the previous network" if ($netnum - 1) < $last_bcast;
        die "Netmask zero illegal, must use a minimum of 2x /1 networks" if !$mask;
        push(@nets, [$netnum, $mask, $CCODES{$cc}]);
        $last_bcast = $netnum + $hostmask;
    }
    die "No networks found in your input!" if !defined $printnet;
    die "Last portion of address space missing after '$printnet'" if $last_bcast != 0xFFFFFFFF;

    return \@nets;
}

sub _make_db {
    my $nets = shift;
    my $ncount = scalar(@$nets);
    my @recs;
    $recs[0] = { zero => 0, one => 0 };
    my $max_rec = 0; # created so far
    for(my $i = 0; $i < $ncount; $i++) {
        my ($netnum, $mask, $ccid) = @{$nets->[$i]};
        my $soffs = 0; # search offs
        for(my $bpos = 0; $bpos < $mask; $bpos++) {
            my $bit = $netnum & (1 << (31 - $bpos));
            my $which = $bit ? 'one' : 'zero';
            my $this_rec = $recs[$soffs];
            if($this_rec->{$which}) { # traversing existing records
                $soffs = $this_rec->{$which};
            }
            else { # making new records
                if($bpos == ($mask - 1)) { # terminal
                    $this_rec->{$which} = COUNTRY_BEGIN + $ccid;
                }
                else { # non-terminal
                    $max_rec++;
                    $soffs = $max_rec;
                    $this_rec->{$which} = $soffs;
                    $recs[$soffs] = { zero => 0, one => 0 };
                }
            }
        }
    }
    return \@recs;
}

sub _write_db {
    my ($fn, $recs) = @_;
    open(my $fh, '>', $fn) or die "Cannot open '$fn' for writing: $!";
    my $nrecs = scalar(@$recs);
    for(my $i = 0; $i < $nrecs; $i++) {
        my $zero = $recs->[$i]->{zero};
        my $one = $recs->[$i]->{one};
        print $fh pack('CCCCCC',
            $zero & 0xFF,
            ($zero & 0xFF00) >> 8,
            ($zero & 0xFF0000) >> 16,
            $one & 0xFF,
            ($one & 0xFF00) >> 8,
            ($one & 0xFF0000) >> 16,
        );
    }
    print $fh pack('CCC', 0xFF, 0xFF, 0xFF);
    close($fh) or die "Cannot close '$fn': $!";
}

sub make_fake_geoip { _write_db($_[0], _make_db(_parse_input($_[1]))); }

1;
