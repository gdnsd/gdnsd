#    Copyright © 2012 Brandon L Black <blblack@gmail.com>
#
#    This file is part of gdnsd.
#
#    gdnsd is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    gdnsd is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
#

package _GDT;

# This should provide the common test functionality,
#  such as executing gdnsd in a forked child running
#  a test-specific dataset, and methods for running
#  queries against it and validating the output against
#  a pre-defined specification

require 5.008001;
use strict;
use warnings;
use POSIX ':sys_wait_h';
use Scalar::Util qw/looks_like_number/;
use FindBin ();
use File::Spec ();
use Net::DNS::Resolver ();
use Net::DNS ();
use LWP::UserAgent ();
use Test::More ();
use File::Copy qw//;
use Socket qw/AF_INET/;
use Socket6 qw/AF_INET6 inet_pton/;
use IO::Socket::INET6 qw//;
use File::Path qw//;
use Config;

# The generic rr-matching code assumes "$rr->string eq $rr->string" is sufficient
#   to detect a test-failure difference between two RRs.  However, the stock ->string
#   code in Net::DNS::RR::OPT doesn't actually print the RDATA portion of OPT RRs,
#   which is where the option code + data live for e.g. edns-client-subnet.  Further,
#   even with ->string fixed, it was discovered that ->new wasn't actually decoding
#   the option data properly anyways.  Both are hacked below to make our test comparisons
#   actually detect failures...
# Arguably we could just patch our local copy directly instead of hacking methods,
#   but I'd rather keep our copy of Net::DNS relatively clean for now, pending whatever
#   comes of all that.
use Net::DNS::RR::OPT;
{
    no warnings 'redefine';

    # The only difference here is removal of the buggy 'unpack("n",...)' from
    #  the decoding of "optiondata"
    *Net::DNS::RR::OPT::new = sub {
	    my ($class, $self, $data, $offset) = @_;

	    $self->{"name"} = "" ;   # should allway be "root"
	    if ($self->{"rdlength"} > 0) {
		    $self->{"optioncode"}   = unpack("n", substr($$data, $offset, 2));
		    $self->{"optionlength"} = unpack("n", substr($$data, $offset+2, 2));
		    $self->{"optiondata"}   = substr($$data, $offset+4, $self->{"optionlength"});
	    }

	    $self->{"_rcode_flags"}  = pack("N",$self->{"ttl"});

	    $self->{"extendedrcode"} = unpack("C", substr($self->{"_rcode_flags"}, 0, 1));
	    $self->{"ednsversion"}   = unpack("C", substr($self->{"_rcode_flags"}, 1, 1));
	    $self->{"ednsflags"}     = unpack("n", substr($self->{"_rcode_flags"}, 2, 2));

	    return bless $self, $class;
    };

    # This was changed to actually reflect optioncode/data differences in the string output
    *Net::DNS::RR::OPT::string = sub {
        my $self = shift;
        my $basics =
            "; EDNS Version "     . $self->{"ednsversion"} .
            "\t UDP Packetsize: " .  $self->{"class"} .
            "\n; EDNS-RCODE:\t"   . $self->{"extendedrcode"} .
            " (" . $Net::DNS::RR::OPT::extendedrcodesbyval{ $self->{"extendedrcode"} }. ")" .
            "\n; EDNS-FLAGS:\t"   . sprintf("0x%04x", $self->{"ednsflags"}) .
            "\n";
        # Technically, there can be multiple options, but the rest of Net::DNS::RR:OPT
        #  just assumes one and ignores any others, and that's all we really need for now anyways
        my $optdata = "";
        if($self->{"optioncode"}) {
            $optdata =
                "; EDNS Option Code: " . $self->{"optioncode"} .
                "\n; EDNS Option Len: " . $self->{"optionlength"} .
                "\n; EDNS Option Hex Data: " . unpack('H*', $self->{"optiondata"}) .
                "\n";
        }

        return $basics . $optdata;
    };
}

sub safe_rmtree {
    my $target = shift;
    if(-e $target) {
        File::Path::rmtree($target, 0, 1);
        if(-e $target) {
            die "Could not rmtree '$target': $!";
        }
    }
}

my %SIGS;
{
    defined $Config{sig_name} || die "No sigs?";
    defined $Config{sig_num} || die "No sigs?";
    my @names = split(' ', $Config{sig_name});
    @SIGS{@names} = split(' ', $Config{sig_num});
}

# Set up per-testfile output directory, zones input directory,
#   and $TEST_SERIAL.
our $OUTDIR;
our $TEST_SERIAL;
our $ALTZONES_IN = $FindBin::Bin . '/altzones/';
{
    my $tname = $FindBin::Bin;
    $tname =~ s{^.*/}{};
    $tname .= '_' . $FindBin::Script;
    $tname =~ s{\.t$}{};
    $OUTDIR = $ENV{TESTOUT_DIR} . '/' . $tname;

    $FindBin::Script =~ m{^0*([0-9]{1,3})}
        or die "Cannot figure out TEST_SERIAL value for $tname";
    $TEST_SERIAL = $1;
}

# generic flag to eliminate various timer delays under testing
$ENV{GDNSD_TESTSUITE_NODELAY} = 1;

our $TEST_RUNNER = "";
if($ENV{TEST_RUNNER}) {
    $TEST_RUNNER = $ENV{TEST_RUNNER};
}

our $TESTPORT_START = $ENV{TESTPORT_START};
die "Test port start specification is not a number"
    unless looks_like_number($TESTPORT_START);

our $DNS_PORT = $TESTPORT_START + (5 * $TEST_SERIAL);
our $HTTP_PORT = $DNS_PORT + 1;
our $EXTRA_PORT  = $DNS_PORT + 2;
our $DNS_SPORT4 = $DNS_PORT + 3;
our $DNS_SPORT6 = $DNS_PORT + 4;

our $saved_pid;

# If user runs testsuite as root, we try to set the privdrop
#   user to nobody as a more-reliable choice.  Failing that,
#   hopefully they read the large warning at the start of
#   the testsuite output...
our $PRIVDROP_USER = ($> == 0) ? 'nobody' : '';

our $GDNSD_BIN = $ENV{INSTALLCHECK_SBINDIR}
    ? "$ENV{INSTALLCHECK_SBINDIR}/gdnsd"
    : "$ENV{TOP_BUILDDIR}/src/gdnsd";

our $EXTMON_BIN = $ENV{INSTALLCHECK_BINDIR}
    ? "$ENV{INSTALLCHECK_BINDIR}/gdnsd_extmon_helper"
    : "$ENV{TOP_BUILDDIR}/plugins/gdnsd_extmon_helper";

# During installcheck, the default hardcoded plugin path
#  should work correctly for finding the installed plugins
our $PLUGIN_PATH;
our $EXTMON_HELPER_CFG = '';
if($ENV{INSTALLCHECK_SBINDIR}) {
    $PLUGIN_PATH = "/xxx_does_not_exist";
}
else {
    $PLUGIN_PATH = "$ENV{TOP_BUILDDIR}/plugins/.libs";
    $EXTMON_HELPER_CFG = qq|extmon => { helper_path => "$EXTMON_BIN" }|;
}

our $RAND_LOOPS = $ENV{GDNSD_RTEST_LOOPS} || 100;

my $CSV_TEMPLATE = 
    "uptime\r\n"
    . "([0-9]+)\r\n"
    . "noerror,refused,nxdomain,notimp,badvers,formerr,dropped,v6,edns,edns_clientsub\r\n"
    . "([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\r\n"
    . "udp_reqs,udp_recvfail,udp_sendfail,udp_tc,udp_edns_big,udp_edns_tc\r\n"
    . "([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\r\n"
    . "tcp_reqs,tcp_recvfail,tcp_sendfail\r\n"
    . "([0-9]+),([0-9]+),([0-9]+)\r\n";

my %stats_accum = (
    noerror      => 0,
    refused      => 0,
    nxdomain     => 0,
    notimp       => 0,
    badvers      => 0,
    formerr      => 0,
    dropped      => 0,
    v6           => 0,
    edns         => 0,
    edns_clientsub => 0,
    udp_reqs     => 0,
    udp_sendfail => 0,
    udp_recvfail => 0,
    udp_tc       => 0,
    udp_edns_big => 0,
    udp_edns_tc  => 0,
    tcp_reqs     => 0,
    tcp_recvfail => 0,
    tcp_sendfail => 0,
);

my $_useragent;
sub _get_daemon_csv_stats {
    $_useragent ||= LWP::UserAgent->new(
        protocols_allowed => ['http'],
        requests_redirectable => [],
        max_size => 10240,
        timeout => 3,
    );
    my $response = $_useragent->get("http://127.0.0.1:${HTTP_PORT}/csv");
    if(!$response) {
        return "No response...";
    }
    elsif($response->code != 200) {
        return "Response code was not 200. Response dump:\n" . $response->as_string("\n");
    }
    return $response->content;
}

sub check_stats_inner {
    my ($class, %to_check) = @_;
    my $content = _get_daemon_csv_stats();
    if($content !~ m/^${CSV_TEMPLATE}/s) {
       die "Content does not match CSV_TEMPLATE, content is: " . $content;
    }
    my $csv_vals = {
        uptime          => $1,
        noerror         => $2,
        refused         => $3,
        nxdomain        => $4,
        notimp          => $5,
        badvers         => $6,
        formerr         => $7,
        dropped         => $8,
        v6              => $9,
        edns            => $10,
        edns_clientsub  => $11,
        udp_reqs        => $12,
        udp_recvfail    => $13,
        udp_sendfail    => $14,
        udp_tc          => $15,
        udp_edns_big    => $16,
        udp_edns_tc     => $17,
        tcp_reqs        => $18,
        tcp_recvfail    => $19,
        tcp_sendfail    => $20,
    };

    ## use Data::Dumper; warn Dumper($csv_vals);

    foreach my $checkit (keys %to_check) {
        if($csv_vals->{$checkit} != $to_check{$checkit}) {
            my $ftype = ($csv_vals->{$checkit} < $to_check{$checkit}) ? 'soft' : 'hard';
            die "$checkit mismatch (${ftype}-fail), wanted " . $to_check{$checkit} . ", got " . $csv_vals->{$checkit};
        }
    }

    return;
}

sub check_stats {
    my ($class, %to_check) = @_;
    my $total_attempts = $TEST_RUNNER ? 30 : 10;
    my $attempt_delay = $TEST_RUNNER ? 0.5 : 0.1;
    my $err;
    my $attempts = 0;
    while(1) {
        eval { $class->check_stats_inner(%to_check) };
        $err = $@;
        return unless $err;
        if($err !~ /hard-fail/ && $attempts++ < $total_attempts) {
            select(undef, undef, undef, $attempt_delay * $attempts);
        }
        else {
            die "Stats check failed: $err";
        }
    }
}

sub proc_tmpl {
    my ($inpath, $outpath) = @_;

    open(my $in_fh, '<', $inpath)
        or die "Cannot open test template '$inpath' for reading: $!";
    open(my $out_fh, '>', $outpath)
        or die "Cannot open test template output '$outpath' for writing: $!";

    my $dns_lspec = qq{[ 127.0.0.1, ::1 ]};

    my $http_lspec = qq{[ 127.0.0.1, ::1 ]};

    my $std_opts = qq{
        listen => $dns_lspec
        http_listen => $http_lspec
        dns_port => $DNS_PORT
        http_port => $HTTP_PORT
        plugin_search_path = $PLUGIN_PATH
        run_dir = $OUTDIR/run/gdnsd
        state_dir = $OUTDIR/var/lib/gdnsd
        realtime_stats = true
        zones_rfc1035_quiesce = 1.02
    };

    if($ENV{USE_ZONES_AUTO}) {
        $std_opts .= qq{        zones_rfc1035_auto = true\n};
    }
    else {
        $std_opts .= qq{        zones_rfc1035_auto = false\n};
    }

    if($PRIVDROP_USER) {
        $std_opts .= qq{username = $PRIVDROP_USER\n};
    }

    while(<$in_fh>) {
        s/\@std_testsuite_options\@/$std_opts/g;
        s/\@extra_port\@/$EXTRA_PORT/g;
        # if the test used the extmon helper, pre-execute
        #   it now to do libtool stuff before privdrop, in case
        #   of testsuite running as root.  Otherwise on first
        #   execution libtool tries to write to the builddir as
        #   as the privdrop user.
        if(s/\@extmon_helper_cfg\@/$EXTMON_HELPER_CFG/g && $PRIVDROP_USER) {
            system("$EXTMON_BIN >/dev/null 2>&1");
        }
        print $out_fh $_;
    }

    close($in_fh) or die "Cannot close test template '$inpath': $!";
    close($out_fh) or die "Cannot close test template output '$outpath': $!";
}

sub recursive_templated_copy {
    my ($indir, $outdir) = @_;
    if(opendir(my $dh, $indir)) {
        if(!-d $outdir) {
            mkdir $outdir or die "Cannot create directory $outdir: $!";
        }
        my @files_list = grep { !/^\./ && ! -d $_ } readdir($dh);
        closedir($dh);
        foreach my $f (@files_list) {
            my $in_full = "$indir/$f";
            my $out_full = "$outdir/$f";
            if(-f $in_full) {
                if($f =~ /^(.*)\.tmpl$/) {
                    proc_tmpl($in_full, "$outdir/$1");
                }
                else {
                    File::Copy::copy($in_full, $out_full)
                        or die "Failed to copy '$in_full' to '$out_full': $!";
                }
            }
            elsif(-d $in_full) {
                recursive_templated_copy($in_full, $out_full);
            }
            else {
                die "Test data file is not a regular file or directory: '$in_full'";
            }
        }
    }
}

our $GDOUT_FH; # open fh on gdnsd.out for test_log_output()
our $INOTIFY_ENABLED = 0;

sub daemon_abort {
    my $log_fn = shift;
    open(my $gdout_fh, '<', $log_fn)
        or die "gdnsd failed to finish starting properly, and no output file could be found";
    my $gdout = '';
    while(<$gdout_fh>) { $gdout .= $_ }
    close($gdout_fh);
    die "gdnsd failed to finish starting properly.  output (if any):\n" . $gdout;
}

sub spawn_daemon_setup {
    my ($class, $etcsrc, $geoip_data) = @_;

    $etcsrc ||= "etc";

    safe_rmtree($OUTDIR);

    foreach my $d ($OUTDIR, "${OUTDIR}/etc", "${OUTDIR}/run", "${OUTDIR}/var", "${OUTDIR}/var/lib", "${OUTDIR}/var/lib/gdnsd") {
        mkdir $d or die "Cannot create directory $d: $!";
    }

    if($geoip_data) {
        require _FakeGeoIP;
        my $gdir = "$OUTDIR/etc/geoip";
        mkdir $gdir or die "Cannot create directory $gdir: $!";
        _FakeGeoIP::make_fake_geoip($gdir . "/FakeGeoIP.dat", $geoip_data);
    }

    recursive_templated_copy("${FindBin::Bin}/${etcsrc}", "${OUTDIR}/etc");
}

sub spawn_daemon_execute {
    my $exec_line = $TEST_RUNNER
        ? qq{$TEST_RUNNER $GDNSD_BIN -Dxfc $OUTDIR/etc start}
        : qq{$GDNSD_BIN -Dxfc $OUTDIR/etc start};

    my $daemon_out = $OUTDIR . '/gdnsd.out';

    my $pid = fork();
    die "Fork failed!" if !defined $pid;

    if(!$pid) { # child, exec daemon
        open(STDOUT, '>', $daemon_out)
            or die "Cannot open '$daemon_out' for writing as STDOUT: $!";
        open(STDIN, '<', '/dev/null')
            or die "Cannot open /dev/null for reading as STDIN: $!";
        open(STDERR, '>&STDOUT')
            or die "Cannot dup STDOUT to STDERR: $!";
        exec($exec_line);
    }

    # Used to kill -9 in END block
    $saved_pid = $pid;

    # With a test runner, we recheck for startup success every second for 300 seconds
    # Without a test runner, every 0.1 seconds for 10 seconds
    my $retry_delay = $TEST_RUNNER ? 1 : 0.1;
    my $retry = $TEST_RUNNER ? 300 : 100;

    select(undef, undef, undef, $retry_delay);
    while($retry--) {
        if(-f $daemon_out) {
            open($GDOUT_FH, '<', $daemon_out)
                or die "Cannot open '$daemon_out' for reading: $!";
            my $is_listening;
            while(<$GDOUT_FH>) {
                $INOTIFY_ENABLED = 1 if /\brfc1035: will use inotify for zone change detection$/;
                daemon_abort($daemon_out) if /\bfatal: /; # don't wait around if we see a fatal log entry...
                return $pid if /\bDNS listeners started$/;
            }
            close($GDOUT_FH)
                or die "Cannot close '$daemon_out' for reading: $!";
        }
        select(undef, undef, undef, $retry_delay);
    }

    daemon_abort($daemon_out);
}

sub test_spawn_daemon {
    my $class = shift;

    # reset stats if daemon run multiple times in one testfile
    foreach my $k (keys %stats_accum) { $stats_accum{$k} = 0; }

    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my $pid = eval{
        $class->spawn_daemon_setup(@_);
        $class->spawn_daemon_execute();
    };
    unless(Test::More::ok(!$@ && $pid)) {
        Test::More::diag("Cannot spawn daemon: $@");
        die $@;
    }

    return $pid;
}

sub test_spawn_daemon_setup {
    my $class = shift;

    local $Test::Builder::Level = $Test::Builder::Level + 1;
    eval{
        $class->spawn_daemon_setup(@_);
    };
    unless(Test::More::ok(!$@)) {
        Test::More::diag("Cannot setup daemon: $@");
        die $@;
    }
}

sub test_spawn_daemon_execute {
    my $class = shift;

    # reset stats if daemon run multiple times in one testfile
    foreach my $k (keys %stats_accum) { $stats_accum{$k} = 0; }

    local $Test::Builder::Level = $Test::Builder::Level + 1;
    my $pid = eval{
        $class->spawn_daemon_execute();
    };
    unless(Test::More::ok(!$@ && $pid)) {
        Test::More::diag("Cannot spawn daemon: $@");
        die $@;
    }

    return $pid;
}

##### START RELOAD STUFF

sub send_sigusr1_unless_inotify {
    if(!$INOTIFY_ENABLED) {
        kill('SIGUSR1', $saved_pid)
            or die "Cannot send SIGUSR1 to gdnsd at pid $saved_pid";
    }
}

sub test_log_output {
    my ($class, $texts_in) = @_;

    $texts_in = [ $texts_in ] unless ref $texts_in;

    # convert to hash for deletions...
    my $i = 0;
    my $texts = { map { $i++ => $_ } @$texts_in };

    my $ok = 0;
    # $retry_delay doubles after each wait...
    my $retry_delay = 0.1;
    my $retry = $TEST_RUNNER ? 10 : 9;
    while($retry--) {
        while(scalar(keys %$texts) && ($_ = <$GDOUT_FH>)) {
            foreach my $k (keys %$texts) {
                my $this_text = $texts->{$k};
                if($_ =~ /\Q$this_text\E/) {
                    delete $texts->{$k};
                    last;
                }
            }
        }
        if(scalar(keys %$texts)) {
            select(undef, undef, undef, $retry_delay);
            $retry_delay *= 2;
        }
        else { last; }
    }

    # do a final delay under valgrind, because technically it's often
    #   the case that we still have a prcu swap to do after the log
    #   message is emitted, before test results are reliable...
    if($TEST_RUNNER) {
        select(undef, undef, undef, $retry_delay);
    }

    if(!scalar(keys %$texts)) {
        Test::More::ok(1);
    }
    else {
        Test::More::ok(0);
        foreach my $v (values %$texts) {
            Test::More::diag("Failed to match log output '$v' in a reasonable timeframe");
        }
    }
}

sub insert_altzone {
    my ($class, $fn, $destfn) = @_;
    my $full_temp_fn = $OUTDIR . "/etc/zones/.mvtmp.$destfn";
    my $full_dest_fn = $OUTDIR . "/etc/zones/$destfn";
    File::Copy::copy("$ALTZONES_IN/$fn", $full_temp_fn)
        or die "Failed to copy alt zonefile '$fn' to '$full_temp_fn': $!";
    File::Copy::move($full_temp_fn, $full_dest_fn)
        or die "Failed to move '$full_temp_fn' to '$full_dest_fn': $!";
}

sub delete_altzone {
    my ($class, $fn) = @_;
    unlink($OUTDIR . "/etc/zones/$fn")
        or die "Failed to unlink zonefile '$fn': $!";
}

sub write_statefile {
    my ($class, $fn, $content) = @_;
    $fn = $OUTDIR . '/var/lib/gdnsd/' . $fn;
    my $fn_tmp = "${fn}.tmp";
    open(my $fd_tmp, ">$fn_tmp")
        or die "Cannot open state file '$fn_tmp' for writing: $!";
    print $fd_tmp $content;
    close($fd_tmp)
        or die "Cannot close state file '$fn_tmp': $!";
    rename($fn_tmp, $fn)
        or die "Cannot rename('$fn_tmp', '$fn'): $!";
}

##### END RELOAD STUFF

my $_resolver;
my $_resolver6;

sub get_resolver {
    return $_resolver ||= Net::DNS::Resolver->new(
        recurse => 0,
        nameservers => [ '127.0.0.1' ],
        port => $DNS_PORT,
        srcport => $DNS_SPORT4,
        srcaddr => '127.0.0.1',
        force_v4 => 1,
        persistent_tcp => 1,
        persistent_udp => 1,
        udp_timeout => 3,
        tcp_timeout => 3,
        retrans => 1,
        retry => 1,
    );
}

sub get_resolver6 {
    return $_resolver6 ||= Net::DNS::Resolver->new(
        recurse => 0,
        nameservers => [ '::1' ],
        port => $DNS_PORT,
        srcport => $DNS_SPORT6,
        srcaddr => '::1',
        force_v6 => 1,
        persistent_tcp => 1,
        persistent_udp => 1,
        udp_timeout => 3,
        tcp_timeout => 3,
        retrans => 1,
        retry => 1,
    );
}

# Creates a new Net::DNS::Packet which is a query response,
#  to compare with the real server response for correctness.
#  Args are: { headerparam => value }, $question, [ answers ], [ auths ], [ addtl ]
#  headers bits default to AA and QR on, the rest off, rcode NOERROR, opcode QUERY,
#  note this wont set ID properly, which is almost surely necessary, and should
#  match the question being asked.
sub mkanswer {
    my ($class, $headers, $question, $answers, $auths, $addtl) = @_;

    my $p = Net::DNS::Packet->new();

    # Add the user-supplied data
    $p->push('question', $question) if $question;
    $p->push('answer', $_) foreach @$answers;
    $p->push('authority', $_) foreach @$auths;
    $p->push('additional', $_) foreach @$addtl;

    # Enforce our defaults over Net::DNS's
    $p->header->qr(1);
    $p->header->aa(1);
    $p->header->tc(0);
    $p->header->rd(0);
    $p->header->cd(0);
    $p->header->ra(0);
    $p->header->ad(0);
    $p->header->opcode('QUERY');
    $p->header->rcode('NOERROR');
    $p->header->qdcount(0) if !$question;

    # Apply nondefault header settings from $headers
    foreach my $hfield (keys %$headers) {
        $p->header->$hfield($headers->{$hfield});
    }

    return $p;
}

sub compare_packets {
    my ($class, $answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6) = @_;

    # Defined-ness checks
    if(!defined $answer) {
        if(!defined $compare) { return; }
        die "Answer was undefined when it shouldn't be";
    }
    elsif(!defined $compare) {
        die "Answer was defined when it shouldn't be";
    }

    my $result = _compare_contents($answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
    if($result) {
        my $ans_str = $answer->string;
        my $comp_str = $compare->string;
        die "Packet mismatch! $result\n---Received:\n$ans_str\n---Wanted:\n$comp_str\n(Addr Limits: V4: $limit_v4 V6: $limit_v6)\n";
    }

    return $answer->answersize;
}

sub _compare_contents {
    my ($answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6) = @_;

    # Header checks
    my $ahead = $answer->header;
    my $chead = $compare->header;
    return "ID mismatch" if $ahead->id != $chead->id;
    return "QR mismatch" if $ahead->qr != $chead->qr;
    return "OPCODE mismatch" if $ahead->opcode ne $chead->opcode;
    return "AA mismatch" if $ahead->aa != $chead->aa;
    return "TC mismatch" if $ahead->tc != $chead->tc;
    return "RD mismatch" if $ahead->rd != $chead->rd;
    return "CD mismatch" if $ahead->cd != $chead->cd;
    return "RA mismatch" if $ahead->ra != $chead->ra;
    return "AD mismatch" if $ahead->ad != $chead->ad;
    return "RCODE mismatch" if $ahead->rcode ne $chead->rcode;
    return "QDCOUNT mismatch" if $ahead->qdcount != $chead->qdcount;
    # These are skipped now because:
    # (a) They should be redundant to the more complex checks below, and
    # (b) They get really screwed up in the presence of $limit_v[46],
    #     which is really a pita to fix properly.
    #return "ANCOUNT mismatch" if $ahead->ancount != $chead->ancount;
    #return "NSCOUNT mismatch" if $ahead->nscount != $chead->nscount;
    #return "ADCOUNT mismatch" if $ahead->adcount != $chead->adcount;

    # Question checks
    my ($aquest) = $answer->question;
    my ($cquest) = $compare->question;
    my $aquest_str = $aquest ? $aquest->string : "";
    my $cquest_str = $cquest ? $cquest->string : "";
    return "Question mismatch" if $aquest_str ne $cquest_str;

    # Section content checks...
    my $ans_rv = _compare_sections("answer", $answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
    return $ans_rv if $ans_rv;
    my $auth_rv = _compare_sections("authority", $answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
    return $auth_rv if $auth_rv;
    my $addtl_rv = _compare_sections("additional", $answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
    return $addtl_rv if $addtl_rv;

    return undef;
}

# Compare two sections by rrset, allowing random re-ordering of whole rrsets
#   as well as rotational offset within an rrset
sub _compare_sections {
    my ($section, $answer, $compare, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6) = @_;
    my $a_rrsets = _get_rrsets($section, $answer);
    my $c_rrsets = _get_rrsets($section, $compare);

    return "$section mismatch: number of rrsets" unless @$a_rrsets == @$c_rrsets;

    my $i = 0;
    my $c_rrsets_href = { map { $i++ => $_ } @$c_rrsets };

    for(my $x = 0; $x < @$a_rrsets; $x++) {
        my $rrtype = $a_rrsets->[$x]->[0]->type;
        my $name = $a_rrsets->[$x]->[0]->name;
        my $match_found;
        foreach my $k (keys %$c_rrsets_href) {
            my $crrtype = $c_rrsets_href->{$k}->[0]->type;
            my $cname = $c_rrsets_href->{$k}->[0]->name;
            next if $crrtype ne $rrtype || $cname ne $name;
            my $cmp_err = _compare_rrsets($a_rrsets->[$x], $c_rrsets_href->{$k}, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
            if($cmp_err) {
                return "$section mismatch: response rrset $name $rrtype: $cmp_err";
            }
            else {
                $match_found = 1;
                delete $c_rrsets_href->{$k};
                last;
            }
        }
        return "$section mismatch: response rrset $name $rrtype not matched" unless $match_found;
    }

    return undef;
}

# Compare two rrsets, allowing for any shuffling of RRs between
#  the answer and comparison rrset, and allowing limit_v4/limit_v6
#  to work properly for zonefile directives $LIMIT_V4 and $LIMIT_V6
#  (that is, if limit is < @$c_rrset, look for *exactly* the limit count
#  in the anwer set).
# This function also implements an automatic 1-limit on CNAMEs in
#  the case that $c_rrset has multiple CNAMEs in it.
# Defers to _compare_rrsets_wrr below if the rrset in question has
#  a matching entry in $wrr_v4 or $wrr_v6

sub _compare_rrsets {
    my ($a_rrset, $c_rrset, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6) = @_;

    my $dname = $c_rrset->[0]->name;
    my $rrtype = $c_rrset->[0]->type;
    my $limit = 0;
    my $wrr = undef;
    if($rrtype eq 'A') {
        $wrr = $wrr_v4->{$dname} if exists $wrr_v4->{$dname};
        $limit = $limit_v4;
    }
    elsif($rrtype eq 'AAAA') {
        $wrr = $wrr_v6->{$dname} if exists $wrr_v6->{$dname};
        $limit = $limit_v6;
    }
    elsif($rrtype eq 'CNAME') {
        $limit = 1;
    }

    # Clamp unspecified/excessive limit to @$c_rrset
    if($limit > @$c_rrset || !$limit) { $limit = @$c_rrset; }

    # The wrr-grouped case is way more complicated, offload to another subroutine
    return _compare_rrsets_wrr_grouped($a_rrset, $c_rrset, $limit, $wrr)
        if defined($wrr) && ref($wrr);

    # If wrr single-mode in effect, set limit range 1-1,
    # If wrr multi-mode, set limit range 1-limit,
    # Else, set limit range limit-limit
    my $lmin = $limit;
    my $lmax = $limit;
    if(defined($wrr)) {
        $lmin = 1;
        $lmax = $wrr ? $limit : 1;
    }

    # Check limit range
    my $asize = scalar @$a_rrset;
    return "rrset size too big ($asize > $lmax)" if $asize > $lmax;
    return "rrset size too small ($asize < $lmin)" if $asize < $lmin;

    # Match every element of $a_rrset to one from $c_rrset, deleting
    #   each match from the comparison set as we go to avoid allowing
    #   duplicate RRs in $a_rrset to succeed.
    #  (deletion happens in the @comp_idx array, so we don't touch the
    #   original comparison data).
    my @comp_idx = (0 .. $#$c_rrset);
    my $found = 0;
    for(my $i = 0; $i < scalar @$a_rrset; $i++) {
        for(my $j = 0; $j < scalar @comp_idx; $j++) {
           if($a_rrset->[$i]->string eq $c_rrset->[$comp_idx[$j]]->string) {
              $found++;
              splice(@comp_idx, $j, 1);
              last;
           }
        }
    }

    return "rrset matched too few ($found < $lmin)" if $found < $lmin;

    return undef; # success!
}

# wrr_v4 and wrr_v6 are primarily to allow testing random-weighted
#  results from plugin_weighted, allowing the testsuite to follow the
#  behavior of all of the address cases (grouped/ungrouped, single/multi):
# wrr_v4 => { 'www.example.com' => 0 } # or 1
#  ^ per-domainname value is 0/1 to indicate single/multi, which checks
#   the limits as exactly 1, or 1-Size.  This covers the ungrouped cases.
# wrr_v4 => { 'www.example.com' => {
#   multi => 0, # or 1
#   groups => [ 2, 2, 3 ]
# }}
# ^ Indicates the comparison RRset has 7 RRs, which are to be split in-order
#   into sub-rrsets of 2, 2, 3 corresponding to plugin_weighted groups, and
#   compared according to multi/single style as indicated by 'multi'.
#  In multi => 1 mode, the comparison will check for exactly 1 match within
#   each sub-set, and matching 1+ subsets overall.
#  In multi => 0 mode, the comparison will check for 1-Size matching RRs
#   from exactly one subset.

sub _compare_rrsets_wrr_grouped {
    my ($a, $c, $limit, $wrr) = @_;

    my $multi = $wrr->{multi};
    my $groups = $wrr->{groups};
    if($multi) {
        my @groupsets;
        my $crr = 0; # index into actual, whole comparison rr-set 
        # pre-create an array of arrayrefs, each arrayref containing
        #   the indices to @$c for a single group
        foreach my $gsize (@$groups) {
            # @grp contains @$c indices for this group
            push(@groupsets, [($crr .. ($crr + $gsize - 1))]);
            $crr += $gsize;
        }
        my $asize = scalar @$a;
        my $found = 0;
        # check all @$a ...
        for(my $i = 0; $i < $asize; $i++) {
            # against all remaining groupsets...
            for(my $j = 0; $j < scalar @groupsets; $j++) {
                foreach my $idx (@{$groupsets[$j]}) {
                   # if we match any entry from this group,
                   if($a->[$i]->string eq $c->[$idx]->string) {
                      # count a cucess
                      $found++;
                      # do no match any more from this whole group
                      splice(@groupsets, $j, 1);
                      last;
                   }
                }
            }
        }
        # success if every @$a matched correctly above
        return undef if($found == $asize);
        return "No matching wrr-multi-group found!";
    }
    else {
        my $asize = scalar @$a;
        my $crr = 0; # index into actual, whole comparison rr-set 
        # For-each group, having size $gsize ...
        foreach my $gsize (@$groups) {
            # @grp contains @$c indices for this group
            my @grp = ($crr .. ($crr + $gsize - 1));
            $crr += $gsize;
            my $found = 0;
            # check all @$a ...
            for(my $i = 0; $i < $asize; $i++) {
                # against all unused @$c[@grp] (splice-out matches as we go)
                for(my $j = 0; $j < scalar @grp; $j++) {
                   if($a->[$i]->string eq $c->[$grp[$j]]->string) {
                      $found++;
                      splice(@grp, $j, 1);
                      last;
                   }
                }
            }
            # success if every @$a matched something in @$c from this one group
            return undef if($found == $asize);
        }
        return "No matching wrr-single-group found!";
    }

}

# Split the RRs of a section (of a packet) into rrsets
sub _get_rrsets {
    my ($section, $packet) = @_;

    my $rrsets = [];
    my $rrsets_idx = 0;

    my @rrs = $packet->$section;
    for(my $rrs_idx = 0; $rrs_idx < @rrs; $rrs_idx++) {
        push(@{$rrsets->[$rrsets_idx]}, $rrs[$rrs_idx]);
        # If 1+ RRs remain after the one just pushed and the
        #  next has a different name or type than the current,
        #  increment the rrsets_idx.
        $rrsets_idx++ if $rrs_idx < @rrs - 1 &&
            ( $rrs[$rrs_idx]->type ne $rrs[$rrs_idx + 1]->type
            || $rrs[$rrs_idx]->name ne $rrs[$rrs_idx + 1]->name )
    }

    return $rrsets;
}

sub query_server {
    my ($class, $qpacket_raw, $query, $expected, $transport, $ro, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6) = @_;

    $limit_v4 ||= 0;
    $limit_v6 ||= 0;

    my $size = 0;

    # Note qpacket_raw only does UDP...
    if($qpacket_raw) {
        my $sockclass = ($transport eq 'IPv6') ? 'IO::Socket::INET6' : 'IO::Socket::INET';
        my $ns = ($transport eq 'IPv6') ? '::1' : '0.0.0.0';
        my $port = $DNS_PORT;
        my $sock = $sockclass->new(
            PeerAddr => $ns,
            PeerPort => $port,
            LocalPort => ($transport eq 'IPv6') ? $DNS_SPORT6 : $DNS_SPORT4,
            ReuseAddr => 1,
            Proto => 'udp',
            Timeout => 10,
        );
        send($sock, $qpacket_raw, 0);
        if($expected) {
            $expected->header->id($query->header->id);
            my $res_raw;
            recv($sock, $res_raw, 4096, 0);
            my $rpkt = Net::DNS::Packet->new(\$res_raw, 1);
            $size = _GDT->compare_packets($rpkt, $expected, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
        }
        close($sock);
    }
    else {
        my $res = ($transport eq 'IPv6') ? get_resolver6() : get_resolver();

        # save resolver opts if we're changing them
        my %saveopts;
        foreach my $k (keys %$ro) {
            $saveopts{$k} = $res->$k();
            $res->$k($ro->{$k})
        }

        if($expected) {
            $expected->header->id($query->header->id);
            $size = _GDT->compare_packets($res->send($query), $expected, $limit_v4, $limit_v6, $wrr_v4, $wrr_v6);
        }
        else {
            $res->bgsend($query);
        }

        # restore altered resolver options
        foreach my $k (keys %saveopts) {
           $res->$k($saveopts{$k});
        }
    }

    return $size;
}

sub test_dns {
    my ($class, %args) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;

    $args{qname}    ||= '.';
    $args{qtype}    ||= 'A';
    $args{header}   ||= {};
    $args{stats}    ||= [qw/udp_reqs noerror/];
    $args{resopts}  ||= {};
    $args{limit_v4} ||= 0;
    $args{limit_v6} ||= 0;
    $args{wrr_v4}   ||= {};
    $args{wrr_v6}   ||= {};
    $args{rep}      ||= 1;

    foreach my $sec (qw/answer auth addtl/) {
        my $aref;
        if(!exists $args{$sec}) {
            $aref = $args{$sec} = [];
        }
        elsif(!ref $args{$sec} || ref $args{$sec} ne 'ARRAY') {
            $aref = $args{$sec} = [$args{$sec}];
        }
        else {
            $aref = $args{$sec};
        }
        map { if(!ref $aref->[$_]) { $aref->[$_] = Net::DNS::RR->new_from_string($aref->[$_]) } } (0..$#$aref);
    }

    my $question = $args{qpacket} || Net::DNS::Packet->new($args{qname}, $args{qtype});
    if(defined $args{qid}) {
        $question->header->id($args{qid});
    }
    if(defined $args{q_optrr}) {
        $question->push(additional => $args{q_optrr});
    }

    my $answer = $args{nores}
        ? undef
        : $class->mkanswer(
            $args{header},
            $args{noresq} ? undef : $question->question(),
            $args{answer},
            $args{auth},
            $args{addtl},
        );

    my ($size4, $size6) = (0, 0);

    if(!$args{v6_only}) {
        for my $i (1 .. $args{rep}) {
            foreach my $stat (@{$args{stats}}) {
                $stats_accum{$stat}++;
            }
            $size4 = eval { $class->query_server($args{qpacket_raw}, $question, $answer, 'IPv4', $args{resopts}, $args{limit_v4}, $args{limit_v6}, $args{wrr_v4}, $args{wrr_v6}) };
            if($@) {
                Test::More::ok(0);
                Test::More::diag("IPv4 query failed: $@");
                return $size4;
            }
        }
    }

    if(!$args{v4_only}) {
        for my $i (1 .. $args{rep}) {
            foreach my $stat (@{$args{stats}}) {
                $stats_accum{$stat}++;
                if($stat eq 'tcp_reqs' || $stat eq 'udp_reqs') {
                    $stats_accum{v6}++;
                }
            }
            $size6 = eval { $class->query_server($args{qpacket_raw}, $question, $answer, 'IPv6', $args{resopts}, $args{limit_v4}, $args{limit_v6}, $args{wrr_v4}, $args{wrr_v6}) };
            if($@) {
                Test::More::ok(0);
                Test::More::diag("IPv6 query failed: $@");
                return $size6;
            }
        }
    }

    eval { $class->check_stats(%stats_accum) };
    Test::More::ok(!$@) or Test::More::diag("Stats check: $@");

    return $size4 || $size6;
}

sub test_stats {
    my $class = shift;
    local $Test::Builder::Level = $Test::Builder::Level + 1;
    eval { $class->check_stats(%stats_accum) };
    Test::More::ok(!$@) or Test::More::diag("Stats check: $@");
}

sub stats_inc { shift; $stats_accum{$_}++ foreach (@_); }

sub test_kill_daemon {
    my ($class, $pid) = @_;
    local $Test::Builder::Level = $Test::Builder::Level + 1;

    if(!$pid) {
        Test::More::ok(0);
        Test::More::diag("Test Bug: no pid specified?");
        die "Test Bug: no pid specified?";
    }

    if(!kill(0, $pid)) {
        Test::More::ok(0);
        Test::More::diag("Daemon at pid $pid was dead before we tried to shut it down");
        die "Daemon at pid $pid was dead before we tried to shut it down";
    }
    else {
        local $@ = undef;
        my $diestr = "";
        eval {
            local $SIG{ALRM} = sub { die "Failed to kill daemon cleanly at pid $pid"; };
            alarm($TEST_RUNNER ? 60 : 30);
            kill('SIGTERM', $pid);
            waitpid($pid, 0);
        };
        if($@) {
            $diestr = $@;
            kill('SIGKILL', $pid);
            waitpid($pid, 0);
        }

        if(WIFEXITED(${^CHILD_ERROR_NATIVE})) {
            my $ev = WEXITSTATUS(${^CHILD_ERROR_NATIVE});
            if($ev) {
                Test::More::ok(0);
                Test::More::diag("$diestr - Exit value was $ev");
                die "$diestr - Exit value was $ev";
            }
        }
        elsif(WIFSIGNALED(${^CHILD_ERROR_NATIVE})) {
            my $s = WTERMSIG(${^CHILD_ERROR_NATIVE});
            if($s != $SIGS{'TERM'}) {
                Test::More::ok(0);
                Test::More::diag("$diestr - Terminated by signal $s");
                die "$diestr - Terminated by signal $s";
            }
        }
    }

    Test::More::ok(1);
}

my $EDNS_CLIENTSUB_OPTCODE = 0x0008;
sub optrr_clientsub {
    my %args = @_;
    $args{scope_mask} ||= 0;

    my %option;

    if(defined $args{addr_v4} || defined $args{addr_v6}) {
        my $src_mask = $args{src_mask};
        my $addr_bytes = ($src_mask >> 3) + (($src_mask & 7) ? 1 : 0);
        if(defined $args{addr_v4}) {
            $option{optiondata} = pack('nCCa' . $addr_bytes, 1, $args{src_mask}, $args{scope_mask}, inet_pton(AF_INET, $args{addr_v4}));
            $option{optioncode} = $EDNS_CLIENTSUB_OPTCODE;
        }
        else {
            $option{optiondata} = pack('nCCa' . $addr_bytes, 2, $args{src_mask}, $args{scope_mask}, inet_pton(AF_INET6, $args{addr_v6}));
            $option{optioncode} = $EDNS_CLIENTSUB_OPTCODE;
        }
    }

    Net::DNS::RR->new(
        type => "OPT",
        ednsversion => 0,
        name => "",
        class => 1024,
        extendedrcode => 0,
        ednsflags => 0,
        %option,
    );
}

END { kill('SIGKILL', $saved_pid) if $saved_pid; }
1;
