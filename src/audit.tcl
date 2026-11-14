# netconf-audit core: IOS style config parser and rules.
namespace eval ::nc {
    variable weak {cisco admin password 1234 12345 default}
}

# parse text -> list of {num text parent}; parent is the unindented line a child belongs to ("" at top level)
proc ::nc::parse {text} {
    set out {}
    set parent ""
    set n 0
    foreach raw [split $text "\n"] {
        incr n
        set raw [string trimright $raw "\r"]
        if {[string trim $raw] eq "" || [string index [string trim $raw] 0] eq "!"} {
            if {[string index $raw 0] ne " "} { set parent "" }
            continue
        }
        if {[string index $raw 0] eq " "} {
            lappend out [list $n [string trim $raw] $parent]
        } else {
            set parent [string trim $raw]
            lappend out [list $n $parent ""]
        }
    }
    return $out
}

proc ::nc::hostname {lines} {
    foreach l $lines {
        if {[regexp {^hostname\s+(\S+)} [lindex $l 1] -> h] && [lindex $l 2] eq ""} { return $h }
    }
    return "device"
}

# top-level lines matching a regexp: list of {num text}
proc ::nc::top {lines re} {
    set r {}
    foreach l $lines {
        if {[lindex $l 2] eq "" && [regexp $re [lindex $l 1]]} { lappend r [list [lindex $l 0] [lindex $l 1]] }
    }
    return $r
}

# children (num text) of every parent matching a regexp, with the parent's num
proc ::nc::vty_blocks {lines} {
    # returns list of {parentNum parentText children} for "line vty ..." blocks
    set blocks {}
    foreach l $lines {
        if {[lindex $l 2] eq "" && [regexp {^line vty } [lindex $l 1]]} {
            set kids {}
            foreach k $lines {
                if {[lindex $k 2] eq [lindex $l 1] && [lindex $k 0] > [lindex $l 0]} { lappend kids $k }
            }
            lappend blocks [list [lindex $l 0] [lindex $l 1] $kids]
        }
    }
    return $blocks
}

proc ::nc::finding {sev rule host num msg} {
    return [list $sev $rule "$host:line $num" $msg]
}

# audit text -> list of {severity rule where message}
proc ::nc::audit {text} {
    variable weak
    set lines [parse $text]
    set host [hostname $lines]
    set f {}
    # NC001, NC008, NC010-ish on VTY blocks
    foreach b [vty_blocks $lines] {
        lassign $b num ptext kids
        set transport ""
        set acl 0
        foreach k $kids {
            if {[regexp {^transport input (.*)$} [lindex $k 1] -> t]} { set transport $t }
            if {[regexp {^access-class } [lindex $k 1]]} { set acl 1 }
        }
        if {$transport eq ""} {
            lappend f [finding high NC001 $host $num "$ptext: no transport input restriction, telnet is allowed by default; use 'transport input ssh'"]
        } elseif {[regexp {(^| )(telnet|all)( |$)} $transport]} {
            lappend f [finding high NC001 $host $num "$ptext: transport input $transport allows telnet; use 'transport input ssh'"]
        }
        if {!$acl} {
            lappend f [finding medium NC008 $host $num "$ptext: no access-class, any source can reach the VTY lines"]
        }
    }
    foreach l [top $lines {^enable password }] {
        lappend f [finding high NC002 $host [lindex $l 0] "enable password is stored reversibly or in cleartext; use 'enable secret' with scrypt (type 9)"]
    }
    foreach l [top $lines {^snmp-server community }] {
        regexp {^snmp-server community (\S+)\s*(\S*)} [lindex $l 1] -> name mode
        if {[string tolower $name] in {public private}} {
            lappend f [finding high NC003 $host [lindex $l 0] "SNMP community uses the well-known name '$name'"]
        } elseif {[string toupper $mode] eq "RW"} {
            lappend f [finding high NC003 $host [lindex $l 0] "SNMP community with read-write access; prefer SNMPv3 and read-only"]
        }
    }
    foreach l [top $lines {^username \S+ (privilege \d+ )?password }] {
        lappend f [finding high NC004 $host [lindex $l 0] "local user with 'password' (cleartext or type 7 reversible); use 'secret' with scrypt (type 9)"]
    }
    # NC005 weak default line passwords (value never printed)
    foreach l $lines {
        if {[regexp {^password (?:[0-7] )?(\S+)$} [lindex $l 1] -> pw] && [string tolower $pw] in $weak} {
            lappend f [finding high NC005 $host [lindex $l 0] "line password is a well-known default"]
        }
    }
    foreach l [concat [top $lines {^enable secret 5 }] [top $lines {^username \S+ (privilege \d+ )?secret 5 }]] {
        lappend f [finding medium NC006 $host [lindex $l 0] "MD5 (type 5) secret is weak against offline cracking; use scrypt (type 9) where supported"]
    }
    foreach l [top $lines {^ip http server$}] {
        lappend f [finding medium NC007 $host [lindex $l 0] "plain HTTP management server enabled; use 'no ip http server' or HTTPS with an ACL"]
    }
    if {[llength [top $lines {^logging (host )?\d+\.\d+\.\d+\.\d+|^logging host }]] == 0} {
        lappend f [finding medium NC009 $host 1 "no remote syslog server configured"]
    }
    if {[llength [top $lines {^ip ssh version 2$}]] == 0} {
        lappend f [finding medium NC010 $host 1 "SSH version 2 is not enforced ('ip ssh version 2')"]
    }
    set haspw 0
    foreach l $lines { if {[regexp {^password } [lindex $l 1]]} { set haspw 1 } }
    if {$haspw && [llength [top $lines {^service password-encryption$}]] == 0} {
        lappend f [finding medium NC011 $host 1 "line passwords present and 'service password-encryption' is missing"]
    }
    if {[llength [top $lines {^ntp server }]] == 0} {
        lappend f [finding low NC012 $host 1 "no NTP server: log timestamps cannot be trusted"]
    }
    if {[llength [top $lines {^banner (login|motd) }]] == 0} {
        lappend f [finding low NC012 $host 1 "no login banner"]
    }
    if {[llength [top $lines {^no ip source-route$}]] == 0} {
        lappend f [finding low NC012 $host 1 "IP source routing is not disabled ('no ip source-route')"]
    }
    return $f
}

proc ::nc::rank {sev} { return [lsearch {high medium low info} $sev] }

proc ::nc::sort {findings} {
    return [lsort -command ::nc::cmp $findings]
}
proc ::nc::cmp {a b} {
    set ra [rank [lindex $a 0]]; set rb [rank [lindex $b 0]]
    if {$ra != $rb} { return [expr {$ra < $rb ? -1 : 1}] }
    regexp {^(.*):line (\d+)$} [lindex $a 2] -> ha na
    regexp {^(.*):line (\d+)$} [lindex $b 2] -> hb nb
    set c [string compare $ha $hb]
    if {$c != 0} { return $c }
    if {$na != $nb} { return [expr {$na < $nb ? -1 : 1}] }
    return [string compare [lindex $a 1] [lindex $b 1]]
}

proc ::nc::render_text {nfiles findings} {
    set s "$nfiles files, [llength $findings] findings\n"
    foreach f $findings {
        lassign $f sev rule where msg
        append s [format "%-8s %s %s\n         %s\n" [string toupper $sev] $rule $where $msg]
    }
    return $s
}
proc ::nc::render_tsv {nfiles findings} {
    set s "# $nfiles files, [llength $findings] findings\n"
    foreach f $findings { append s [join $f "\t"] "\n" }
    return $s
}
