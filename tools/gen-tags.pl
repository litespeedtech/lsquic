#!/usr/bin/env perl
#
# Generate tags for lsquic project
#
# If your `ctags' is not Universal Ctags, set UCTAGS environment variable to
# point to it.

use warnings;

use Getopt::Long;

GetOptions("docs!" => \my $do_docs);

$tmpfile = '.tags.' . $$ . rand;
$ctags = $ENV{UCTAGS} || 'ctags';
$queue_h = '/usr/include/sys/queue.h';

@dirs = qw(include bin tests src/lshpack src/liblsquic);

system($ctags, '-f', $tmpfile,
    ('--kinds-c=+p') x !!$do_docs,  # Index function prototypes
    qw(-R -I SLIST_ENTRY+=void -I LIST_ENTRY+=void
    -I STAILQ_ENTRY+=void -I TAILQ_ENTRY+=void -I CIRCLEQ_ENTRY+=void
    -I TAILQ_ENTRY+=void -I SLIST_HEAD+=void -I LIST_HEAD+=void
    -I STAILQ_HEAD+=void -I TAILQ_HEAD+=void -I CIRCLEQ_HEAD+=void
    -I TAILQ_HEAD+=void), @dirs)
        and die "ctags failed";

-f $queue_h
    and system($ctags, '-f', $tmpfile, '-a', $queue_h)
    and die "ctags $queue_h failed";

if ($do_docs) {
    @rst = glob("docs/*.rst");
    if (@rst) {
        system("$^X tools/gen-rst-tags.pl @rst >> $tmpfile")
            and die "cannot run tools/gen-rst-tags.pl";
    }
}

END { unlink $tmpfile }

open TMPFILE, "<", $tmpfile
        or die "cannot open $tmpfile for reading: $!";
while (<TMPFILE>)
{
    push @lines, $_;
    if (
        s/^(mini|full|ietf_full|ietf_mini|evanescent)_conn_ci_/ci_/
     or s/^(nocopy|hash|error)_di_/di_/
     or s/^(gquic)_(be|Q046|Q050)_/pf_/
     or s/^ietf_v[0-9][0-9]*_/pf_/
     or s/^stock_shi_/shi_/
     or s/^iquic_esf_/esf_/
     or s/^gquic[0-9]?_esf_/esf_/
     or s/^iquic_esfi_/esfi_/
     or s/^(lsquic_cubic|lsquic_bbr)_/cci_/
    )
    {
        push @lines, $_;
    }
}
open TMPFILE, ">", $tmpfile
        or die "cannot open $tmpfile for writing: $!";
print TMPFILE sort @lines;
close TMPFILE;
rename $tmpfile, 'tags';
