#!/usr/bin/env perl
#
# Mirrors remote ftp://host/sub/directory/
# to local ./host/sub/directory/
#
# Author: xrgtn

use strict;
use warnings;
use Net::FTP;
use Getopt::Std;
use IO::Socket::SSL;
use File::Path qw(make_path remove_tree);
use IO::Handle;		# ->flush();
use Fcntl ':mode';	# S_IFDIR, S_IFREG etc

my %opts;

sub usage() {
    die  "USAGE: $0 [opts] [(ftp|ftps)://]usr\@host/sub/dir\n"
	."   or: $0 -c [(ftp|ftps)://]host\n"
	." opts:\n"
	."\t-c     print FTP server's certificate and exit\n"
	."\t-d     FTP debug output\n"
	."\t-f FP  verify FTP server against fingerprint FP\n"
	."\t-n     don't preserve permissions\n"
	."\t-u     upload to FTP server insead of downloading\n"
	."\t-v     verbose mode\n";
};

# Print FTP warning message.
sub ftpw($$) {
    my ($ftp, $text) = @_;
    (my $m = $ftp->message()) =~ s/\r*\n$//;
    $m .= ", $@" if defined $@ and $@ ne "";
    print STDERR "WARN: $text - $m\n";
};

# Print FTP error message and die.
sub ftpd($$) {
    my ($ftp, $text) = @_;
    (my $m = $ftp->message()) =~ s/\r*\n$//;
    $m .= ", $@" if defined $@ and $@ ne "";
    die "$text - $m\n";
};

# Write leading-zero-formatted octal version of "perms"
# into "permsXXXX",
sub set_permsXXXX($) {
    my ($f) = @_;
    if ($f->{perms} <= 0777) {
        $f->{permsXXXX} = sprintf "%04o", $f->{perms};
    } else {
        $f->{permsXXXX} = sprintf "0%o", $f->{perms};
    };
};

# Set numeric "perms" field from "ur/uw/ux/gr/gw/gw/or/ow/ox".
# Also write leading-zero-formatted octal value of "perms"
# into "permsXXXX",
sub set_perms($) {
    my ($f) = @_;
    $f->{perms} = 0 if not defined $f->{perms};
    if (defined $f->{ur}) {
	if ($f->{ur} eq "r") {
	    $f->{perms} |=  S_IRUSR;
	} else {
	    $f->{perms} &= ~S_IRUSR;
	};
    };
    if (defined $f->{uw}) {
	if ($f->{uw} eq "w") {
	    $f->{perms} |=  S_IWUSR;
	} else {
	    $f->{perms} &= ~S_IWUSR;
	};
    };
    if (defined $f->{ux}) {
	if ($f->{ux} eq "x") {
	    $f->{perms} |=  S_IXUSR;
	    $f->{perms} &= ~S_ISUID;
	} elsif ($f->{ux} eq "s") {
	    $f->{perms} |=  S_IXUSR|S_ISUID;
	} elsif ($f->{ux} eq "S") {
	    $f->{perms} &= ~S_IXUSR;
	    $f->{perms} |=  S_ISUID;
	} else {
	    $f->{perms} &= ~(S_IXUSR|S_ISUID);
	};
    };
    if (defined $f->{gr}) {
	if ($f->{gr} eq "r") {
	    $f->{perms} |=  S_IRGRP;
	} else {
	    $f->{perms} &= ~S_IRGRP;
	};
    };
    if (defined $f->{gw}) {
	if ($f->{gw} eq "w") {
	    $f->{perms} |=  S_IWGRP;
	} else {
	    $f->{perms} &= ~S_IWGRP;
	};
    };
    if (defined $f->{gx}) {
	if ($f->{gx} eq "x") {
	    $f->{perms} |=  S_IXGRP;
	    $f->{perms} &= ~S_ISGID;
	} elsif ($f->{gx} eq "s") {
	    $f->{perms} |=  S_IXGRP|S_ISGID;
	} elsif ($f->{gx} eq "S") {
	    $f->{perms} &= ~S_IXGRP;
	    $f->{perms} |=  S_ISGID;
	} else {
	    $f->{perms} &= ~(S_IXGRP|S_ISGID);
	};
    };
    if (defined $f->{or}) {
	if ($f->{or} eq "r") {
	    $f->{perms} |=  S_IROTH;
	} else {
	    $f->{perms} &= ~S_IROTH;
	};
    };
    if (defined $f->{ow}) {
	if ($f->{ow} eq "w") {
	    $f->{perms} |=  S_IWOTH;
	} else {
	    $f->{perms} &= ~S_IWOTH;
	};
    };
    if (defined $f->{ox}) {
	if ($f->{ox} eq "x") {
	    $f->{perms} |=  S_IXOTH;
	    $f->{perms} &= ~S_ISVTX;
	} elsif ($f->{ox} eq "t") {
	    $f->{perms} |=  S_IXOTH|S_ISVTX;
	} elsif ($f->{ox} eq "T") {
	    $f->{perms} &= ~S_IXOTH;
	    $f->{perms} |=  S_ISVTX;
	} else {
	    $f->{perms} &= ~(S_IXOTH|S_ISVTX);
	};
    };
    set_permsXXXX($f);
};

# Convert UNIX seconds since 1970 into "hh:mm" or "year" string
# depending on difference with current time.
sub hmy($) {
    my ($t) = @_;
    my @l = localtime($t);
    my $t0 = time();
    if (abs($t - $t0) >= 365*24*3600) {
	return sprintf " %04d", $l[5] + 1900;
    } else {
	return sprintf "%02d:%02d", $l[2], $l[1];
    };
};

# Return file description as a string.
sub descf($) {
    my ($f) = @_;
    my $p = defined $f->{permsXXXX} ? $f->{permsXXXX} : "????";
    my $s = defined $f->{sz} ? $f->{sz} : defined $f->{s} ?
	$f->{s} : 0;
    $s = sprintf "%6d", $s;
    my $hmy = defined $f->{hmy} ? $f->{hmy} : defined $f->{tm} ?
	hmy($f->{tm}) : "??:??";
    return "$f->{type} $p $s $hmy $f->{path}";
};

# Produce FTP directory listing using NLST (when opts->{n} is set)
# or LIST command. The latter is required for preserving
# file permissions.
sub dir($$;$$$) {
    my ($ftp, $opts, $d, $p, $pfx) = @_;
    my ($files, $fhash);
    $d = "." if not defined $d;
    $p = $d if not defined $p;
    $pfx = "" if not defined $pfx;
    if (not defined $opts->{n} or not $opts->{n}) {
	my @lines = $ftp->dir($d);
	if (not $ftp->ok()) {ftpd $ftp, "dir '$p'"};
# crw-rw----+ 1 root kvm      10, 232 Jan 23 14:22 kvm
# srw-rw-rw-  1 root root           0 Jan 23 14:22 log
# brw-rw----  1 root disk      7,   0 Jan 23 14:27 loop0
# drwxr-xr-x  2 root root         220 Jan 23 14:27 mapper
# lrwxrwxrwx  1 root root           4 Jan 23 14:22 rtc -> rtc0
# prw-r-----  1 root adm            0 Jan 23 14:22 xconsole
# -rw-r--r-- 1 root root    98964 Jun 25  2015 memtest86.bin
	foreach my $ln (@lines) {
	    $ln =~ m/^
		(?<tp>
		(?<t>[bcdlps-])		# file type
		(?<p>
		(?<urwx>
		(?<ur>[r-])		# user read perms
		(?<uw>[w-])		# user write perms
		(?<ux>[xsS-])		# user execute perms
		)
		(?<grwx>
		(?<gr>[r-])		# group read perms
		(?<gw>[w-])		# group write perms
		(?<gx>[xsS-])		# group execute perms
		)
		(?<orwx>
		(?<or>[r-])		# others read perms
		(?<ow>[w-])		# others write perms
		(?<ox>[xtT-])		# others execute perms
		)
		(?<a>[+]?)		# has ACLs
		)
		)
		\s+
		(?<l>\d+)		# number of links
		\s+
		(?<usr>[\w-]+)		# user name
		\s+
		(?<grp>[\w-]+)		# group name
		\s+
		(?<mjns>
		(?<m>\d+),\s*(?<n>\d+)	# device major:minor
		|(?<s>\d+)		# or size
		)
		\s+
		(?<md>(?<mon>Jan|Feb	# month
		|Mar|Apr|May|Jun|Jul
		|Aug|Sep|Nov|Dec)
		\s+
		(?<d>\d{1,2}))		# day of month
		\s+
		(?<hmy>
		(?<hm>(?<hh>\d{2})	# hours and
		:(?<mi>\d{2}))		# minutes,
		|(?<y>\d{4,})		# or year
		)
		\s+
		(?<f>.*)		# file name
	    $/x or die "invalid LIST line: $ln";
	    my $f;
	    $f->{ln} = $ln;
	    $f->{$_} = $+{$_} foreach keys %+;
	    $f->{path} = $p eq "." ? $f->{f} : "$p/$f->{f}";
	    set_perms($f);
	    push @$files, $f;
	    $fhash->{$f->{f}} = $f;
	    # print STDOUT "$f->{t}$f->{urwx}$f->{grwx}$f->{orwx}".
	    #	"$f->{a} ".sprintf("%04o", $f->{perms})
	    #	." $f->{usr} $f->{grp} $f->{mjns}"
	    #	." $f->{md} $f->{hmy} $f->{f}\n";
	};
    } else {
	my @lines = $ftp->ls($d);
	if (not $ftp->ok()) {ftpd $ftp, "ls '$p'"};
	foreach my $ln (@lines) {
	    my $f;
	    $f->{ln} = $ln;
	    $f->{f} = $ln;
	    $f->{path} = $p eq "." ? $f->{f} : "$p/$f->{f}";
	    push @$files, $f;
	    $fhash->{$f->{f}} = $f;
	}
    };
    return ($files, $fhash);
};

# If file description was produced by LIST, check file type
# field. Otherwise (description by NLST) use MDTM/SIZE method.
sub check_file_type_and_mtime($$) {
    my ($f, $ftp) = @_;
    if (defined $f->{t}) {
	if ($f->{t} eq "-") {
	    $f->{type} = "f";
	    $f->{tm} = $ftp->mdtm($f->{f});
	    if (not defined $f->{tm} or not $ftp->ok()) {
		ftpd $ftp, "ftp mtime of '$f->{f}'";
	    };
	} else {
	    $f->{type} = $f->{t};
	};
    } else {
	$f->{tm} = $ftp->mdtm($f->{f});
	if (defined $f->{tm} and $ftp->ok()) {
	    $f->{type} = "f?";
	} elsif ($ftp->code() == 550) {
	    # 550 means it is a directory, probably
	    $f->{type} = "d?";
	} else {
	    # XXX: other codes are unknown, so we may mark
	    # the file as one of unknown type and continue,
	    # or die right here right now.
	    $f->{type} = "?";
	    ftpd $ftp, "ftp mtime of '$f->{f}'";
	};
    };
};

# Get file $f from FTP server $ftp. Set mtime and permissions
# after download is finished.
sub get($$$$) {
    my ($f, $ftp, $pfx, $opts) = @_;
    # "download started":
    print STDOUT "${pfx}get   ".descf($f).": ";
    STDOUT->flush();

    $ftp->hash(\*STDOUT, 0x80000);	# print '#' every 512kbytes
    $ftp->get($f->{f}) or ftpd $ftp, "ftp get '$f->{f}'";
    # set mtime:
    utime $f->{tm}, $f->{tm}, $f->{f}
	or die "set mtime of '$f->{f}' - $!";
    # set permissions:
    if (defined $f->{perms}) {
	chmod $f->{perms}, $f->{f}
	    or die "chmod $f->{permsXXXX} $f->{f} - $!";
    };
    print STDOUT "OK\n";		# download finished.
    STDOUT->flush();
};

# Recursively mirror current remote directory to
# current local one.
sub mirr($$;$$);	# declare prototype for recursion.
sub mirr($$;$$) {
    my ($ftp, $opts, $path, $pfx) = @_;
    my ($files, $fhash, $r);
    $path = "." if not defined $path;
    $pfx = "" if not defined $pfx;
    # List remote directory:
    ($files, $fhash) = dir($ftp, $opts, ".", $path, $pfx);
    foreach my $f (@$files) {
	next if $f->{f} eq "." or $f->{f} eq "..";
	check_file_type_and_mtime($f, $ftp);
	if ($f->{type} eq "f" or $f->{type} eq "f?") {
	    if (-f $f->{f}) {
		my @st = stat $f->{f};
		die "stat '$f->{f}' - $!" if not scalar(@st);
		$f->{sz} = $ftp->size($f->{f});
		if (not defined $f->{sz}) {
		    ftpd $ftp, "ftp size of '$f->{f}'"
		};
		if ($f->{sz} == $st[7] and $f->{tm} == $st[9]) {
		    if (defined $f->{perms}
		    and $f->{perms} != ($st[2] & 07777)) {
			print STDOUT "${pfx}chmod ".descf($f)."\n";
			chmod $f->{perms}, $f->{f}
			    or die "chmod $f->{permsXXXX}"
				." $f->{f} - $!";
		    } else {
			print STDOUT "${pfx}skip ".descf($f)."\n"
			    if $opts->{v};
		    };
		} else {
		    get($f, $ftp, $pfx, $opts);
		};
	    } else {
		get($f, $ftp, $pfx, $opts);
	    };
	} elsif ($f->{type} eq "d" or $f->{type} eq "d?") {
	    # Do chdir on remote server to confirm that it's indeed
	    # a directory, then make corresponding local directory,
	    # chdir to it and call mirr() recursively:
	    $ftp->cwd($f->{f}) and $ftp->ok()
		or ftpd $ftp, "ftp cd '$f->{f}'";
	    make_path $f->{f}
		or die "mkdir '$f->{f}' - $!"
		    if not -d $f->{f};
	    # set permissions on a directory:
	    my @st = stat $f->{f};
	    die "stat '$f->{f}' - $!" if not scalar(@st);
	    if (defined $f->{perms}
	    and $f->{perms} != ($st[2] & 07777)) {
		print STDOUT "${pfx}chmod ".descf($f)."\n";
		chmod $f->{perms}, $f->{f}
		    or die "chmod $f->{permsXXXX} $f->{f} - $!";
	    };
	    chdir $f->{f}
		or die "cd '$f->{f}' - $!";
	    print STDOUT "${pfx}cd ".descf($f)."\n"
		if $opts->{v};
	    my $path2 = ($path eq ".") ? $f->{f} : "$path/$f->{f}";
	    mirr($ftp, $opts, $path2, " ".$pfx);
	    # Return to local parent from local directory '$f':
	    chdir ".." or die "cd '..' - $!";
	    # Return to remote parent from remote directory '$f':
	    $ftp->cdup() and $ftp->ok() or ftpd $ftp, "ftp cdup";
	} else {
	    # Skip file of unknown type:
	    print STDOUT "${pfx}skip ".descf($f)."\n";
	};
    };
};

# Fill in local file info (size, mtime, perms etc).
sub stat_file($$) {
    my ($f, $p) = @_;
    $f->{path} = $p eq "." ? $f->{f} : "$p/$f->{f}";
    my @st = lstat $f->{f};
    $f->{perms} = $st[2] & 07777;
    set_permsXXXX($f);
    if (S_ISDIR($st[2])) {
	$f->{type} = "d";
    } elsif (S_ISREG($st[2])) {
	$f->{type} = "f";
    } elsif (S_ISLNK($st[2])) {
	$f->{type} = "l";
    } elsif (S_ISBLK($st[2])) {
	$f->{type} = "b";
    } elsif (S_ISCHR($st[2])) {
	$f->{type} = "c";
    } elsif (S_ISFIFO($st[2])) {
	$f->{type} = "p";	# FIFO == pipe
    } elsif (S_ISSOCK($st[2])) {
	$f->{type} = "s";
    } else {
	$f->{type} = "?";	# unknown type
    };
    $f->{usr} = $st[4];
    $f->{grp} = $st[5];
    $f->{sz}  = $st[7];
    $f->{tm}  = $st[9];
};

# Put file $f to FTP server $ftp. Set permissions afterwards.
sub put($$$$) {
    my ($f, $ftp, $pfx, $opts) = @_;

    print STDOUT "${pfx}put   ".descf($f).": ";	# upload started,
    STDOUT->flush();

    $ftp->hash(\*STDOUT, 0x80000);	# print '#' every 512kbytes
    $ftp->put($f->{f}) or ftpd $ftp, "ftp put '$f->{path}'";

    if (not $opts->{n}) {
	# set permissions:
	$ftp->site("chmod", $f->{permsXXXX}, $f->{f}) and $ftp->ok()
	    or ftpd $ftp, "ftp chmod $f->{permsXXXX} $f->{path}";
    };

    print STDOUT "OK\n";		# upload finished.
    STDOUT->flush();
};

# Recursively mirror current local directory to
# current remote local one.
sub mirr_upload($$;$$);	# declare prototype for recursion.
sub mirr_upload($$;$$) {
    my ($ftp, $opts, $path, $pfx) = @_;
    my ($rfile, $rfhash, $r, @files);
    $path = "." if not defined $path;
    $pfx = "" if not defined $pfx;
    # List remote directory:
    ($rfile, $rfhash) = dir($ftp, $opts, ".", $path, $pfx);
    # List local directory:
    opendir(my $dh, ".") or die "opendir '.' - $!";
    @files = readdir $dh;
    closedir $dh;
    # Decide what to do for each local file:
    foreach my $fn (@files) {
	my $f; $f->{f} = $fn;
	next if $f->{f} eq "." or $f->{f} eq "..";	# skip
	stat_file($f, $path);
	if ($f->{type} eq "f") {
	    if (exists $rfhash->{$f->{f}}) {
		check_file_type_and_mtime($rfhash->{$f->{f}}, $ftp);
		if ($rfhash->{$f->{f}}->{type} eq "d"
		or $rfhash->{$f->{f}}->{type} eq "f?") {
		    # rmdir if it's a directory:
		    $ftp->rmdir($f->{f}, 1) and $ftp->ok()
			or ftpd $ftp, "ftp rmdir '$f->{path}'";
		    print STDOUT "${pfx}rmdir "
			.descf($rfhash->{$f->{f}})."\n";
		    delete $rfhash->{$f->{f}};
		} elsif ($rfhash->{$f->{f}}->{type} ne "f"
		and $rfhash->{$f->{f}}->{type} ne "f?") {
		    # remove if it's not a file:
		    $ftp->delete($f->{f}) and $ftp->ok()
			or ftpd $ftp, "ftp rm '$f->{path}'";
		    print STDOUT "${pfx}rm    "
			.descf($rfhash->{$f->{f}})."\n";
		    delete $rfhash->{$f->{f}};
		} else {
		    $rfhash->{$f->{f}}->{sz} = $ftp->size($f->{f});
		    if (not defined $rfhash->{$f->{f}}->{sz}) {
			ftpd $ftp, "ftp size of '$f->{path}'";
		    };
		};
	    };
	    if (not exists $rfhash->{$f->{f}}
	    or $rfhash->{$f->{f}}->{sz} != $f->{sz}
	    or $rfhash->{$f->{f}}->{tm} != $f->{tm}) {
		put($f, $ftp, $pfx, $opts);
	    } else {
		print STDOUT "${pfx}skip  ".descf($f)."\n";
	    };
	} elsif ($f->{type} eq "d") {
	    if (exists $rfhash->{$f->{f}}) {
		check_file_type_and_mtime($rfhash->{$f->{f}}, $ftp);
		if ($rfhash->{$f->{f}}->{type} ne "d"
		and $rfhash->{$f->{f}}->{type} ne "d?") {
		    # remove if it's not a directory:
		    $ftp->delete($f->{f}) and $ftp->ok()
			or ftpd $ftp, "ftp rm '$f->{path}'";
		    print STDOUT "${pfx}rm    "
			.descf($rfhash->{$f->{f}})."\n";
		    delete $rfhash->{$f->{f}};
		};
	    };
	    # create if it doesn't exist:
	    if (not exists $rfhash->{$f->{f}}) {
		$ftp->mkdir($f->{f}) and $ftp->ok()
		    or ftpd $ftp, "ftp mkdir '$f->{path}'";
		# XXX: report mkdir after both mkdir and chmod:
	    };
	    if (not $opts->{n} and (not exists $rfhash->{$f->{f}} or
	    $rfhash->{$f->{f}}->{perms} != $f->{perms})) {
		# set permissions on a directory:
		$ftp->site("chmod", $f->{permsXXXX}, $f->{f})
		and $ftp->ok()
		    or ftpd $ftp, "ftp chmod $f->{permsXXXX}"
			." '$f->{path}'";
		# report chmod on existing directories only:
		if (exists $rfhash->{$f->{f}}) {
		    print STDOUT "${pfx}chmod ".descf($f)."\n";
		};
	    };
	    if (not exists $rfhash->{$f->{f}}) {
		# XXX: delayed mkdir report:
		print STDOUT "${pfx}mkdir ".descf($f)."\n";
	    };
	    # change into directory $f:
	    $ftp->cwd($f->{f}) and $ftp->ok()
		or ftpd $ftp, "ftp cd '$f->{path}'";
	    chdir $f->{f}
		or die "cd '$f->{path}' - $!";
	    print STDOUT "${pfx}cd    ".descf($f)."\n"
		if $opts->{v};
	    my $path2 = ($path eq ".") ? $f->{f} : "$path/$f->{f}";
	    mirr_upload($ftp, $opts, $path2, " ".$pfx);
	    # Return to local parent from local directory '$f':
	    chdir ".." or die "cd '$path2/..' - $!";
	    # Return to remote parent from remote directory '$f':
	    $ftp->cdup() and $ftp->ok() or ftpd $ftp, "ftp cdup";
	} else {
	    # skip device files, sockets, FIFOs and symlinks:
	    print STDOUT "${pfx}skip  ".descf($f)."\n";
	};
    };
};

usage if not getopts "cdf:nuv", \%opts;
usage if scalar(@ARGV) < 1;
$ARGV[0] =~ m{^(?:(ftp[s0]?)://)?(?:([^@]+)@)?([^/]+)(?:/+(.*))?$}i
    or die "ERROR: invalid FTP URL - $ARGV[0]\n";

my $ftpproto = defined $1 ? lc($1) : "ftp";
my $ftpuser = defined $2 ? $2 : "anonymous";
my $ftphost = $3;
my $remotedir = defined $4 && $4 ne "" ? $4 : ".";
my $localdir = defined $ARGV[1] && $ARGV[1] ne "" ? $ARGV[1] :
    $remotedir ne "." ? "$ftphost/$remotedir" : $ftphost;

my $ftp = Net::FTP->new($ftphost, Timeout=>15, Passive=>1,
	Debug=>$opts{d},
	SSL=>($ftpproto eq "ftps"),
	SSL_ocsp_mode=>SSL_OCSP_FULL_CHAIN,
	SSL_verify_mode=>(defined $opts{c} ?
	    SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_PEER),
	SSL_fingerprint=>(defined $opts{f} ? $opts{f} : undef)
	)
    or die "ERROR: $@\n";
eval {
    if ($ftpproto eq "ftp") {
	$ftp->starttls() or ftpd $ftp, "cannot start TLS";
    };
    if ($opts{c}) {
	die "$ftpproto not supported with -c\n"
	    if $ftpproto ne "ftp" and $ftpproto ne "ftps";
	print STDOUT "'$ftphost' cert:\n";
	print STDOUT "  ".$ftp->get_fingerprint($_)."\n"
	    foreach qw(md5 sha1 sha256 sha512);
	print STDOUT "  ca: ".$ftp->peer_certificate(
	    "authority")."\n";
	print STDOUT "  owner: ".$ftp->peer_certificate(
	    "owner")."\n";
	print STDOUT "  cn: ".$ftp->peer_certificate(
	    "commonName")."\n";
	my @a = $ftp->peer_certificate("subjectAltNames");
	for (my $i = 1; $i < scalar(@a); $i += 2) {
	    print STDOUT "  altn: $a[$i]\n";
	};
	goto QUIT_FTP;
    };
    $ftp->login($ftpuser) or ftpd $ftp, "ftp login '$ftpuser'";
    $ftp->binary() or ftpd $ftp, "cannot switch to Binary mode";
    #$ftp->prot("P") or ftpw $ftp, "cannot switch data channel to"
    #	." Private";
    if ($localdir ne ".") {
	if (not $opts{u} and not -e $localdir) {
	    make_path $localdir or die "mkdir '$localdir' - $!";
	};
	chdir $localdir or die "cd '$localdir' - $!";
    };
    if ($remotedir ne ".") {
	if ($remotedir =~ m{^/}) {
	    die "invalid remote dir '$remotedir'";
	};
	# TODO: don't fail in upload mode when
	# remote directory doesn't exist
	$ftp->cwd($remotedir) and $ftp->ok()
	    or ftpd $ftp, "ftp cd '$remotedir'";
    };
    if ($opts{u}) {
	mirr_upload($ftp, \%opts, $remotedir);
    } else {
	mirr($ftp, \%opts, $remotedir);
    };
QUIT_FTP:
};
my $err = defined $@ ? $@ : "";
if ($err ne "") {
    print STDERR "ERR: $err\n";
};
$ftp->quit();

# vi:set sw=4 noet ts=8 tw=71:
