#!/usr/bin/env perl
#
# Parse .rst files and generate tags.

use strict;
use warnings;

my $id = '[a-zA-Z_0-9]';
my @tags;
for my $file (@ARGV) {
    open my $fh, '<', $file
        or die "Cannot open $file for reading: $!";
    while (<$fh>) {
        chomp;
        if (m/^(\.\. function:: )(.+)/) {
            my ($pfx, $val) = ($1, $2);
            if ($val =~ m/($id+) \(/o) {
                push @tags, "$1\t$file\t/^$pfx$val/\n";
            } else {
                warn "unknown pattern in $file:$.: $_\n";
            }
        } elsif (m/^(\s*\.\. (?:type|member):: )(.+)/) {
            my ($pfx, $val) = ($1, $2);
            if ($val =~ m/\(\*([^\)]+)\)/) {
                push @tags, "$1\t$file\t/^$pfx$val/\n";
            } elsif ($val =~ m/($id+)(?::\d+)?\s*$/o) {
                push @tags, "$1\t$file\t/^$pfx$val/\n";
            } else {
                warn "unknown pattern in $file:$.: $_\n";
            }
        } elsif (m/^(\s*\.\. var:: )(.+)/) {
            my ($pfx, $val) = ($1, $2);
            if ($val =~ m/($id+)(?:\[[^\]]*\])?\s*$/o) {
                push @tags, "$1\t$file\t/^$pfx$val/\n";
            } else {
                warn "unknown pattern in $file:$.: $_\n";
            }
        } elsif (m/^(\s*\.\. macro::\s+)(\S+)\s*$/) {
            push @tags, "$2\t$file\t/^$1$2/\n";
        } elsif (m/^\s*\.\. (?:toctree|image|highlight|code-block)::/) {
            # Skip
        } elsif (m/^\s*\.\.\s*\S+::/) {
            warn "unknown pattern in $file:$.: $_\n";
        }
    }
}

print sort @tags;
