package require tcltest
namespace import ::tcltest::*
set root [file normalize [file join [file dirname [info script]] ..]]
source [file join $root src audit.tcl]

proc rules {text} { set r {}; foreach f [::nc::audit $text] { lappend r [lindex $f 1] }; return [lsort -unique $r] }
proc has {text rule sev} { foreach f [::nc::audit $text] { if {[lindex $f 1] eq $rule && [lindex $f 0] eq $sev} { return 1 } }; return 0 }
proc count {text rule} { set n 0; foreach f [::nc::audit $text] { if {[lindex $f 1] eq $rule} { incr n } }; return $n }
set base "hostname t1\nlogging host 192.0.2.1\nntp server 192.0.2.2\nip ssh version 2\nno ip source-route\nbanner login ^C hi ^C\n"
set vtyok "line vty 0 4\n access-class MGMT in\n transport input ssh\n"

test parse-1 {parent assignment} -body {
    set l [::nc::parse "hostname a\nline vty 0 4\n transport input ssh\n!\ninterface Gi0\n shutdown\n"]
    list [lindex $l 2 2] [lindex $l 4 2] [lindex $l 1 2]
} -result {{line vty 0 4} {interface Gi0} {}}
test parse-2 {line numbers are 1-based and skip comments} -body {
    lindex [::nc::parse "!\n!\nhostname a\n"] 0 0
} -result 3
test parse-3 {CRLF files} -body { lindex [::nc::parse "hostname a\r\n"] 0 1 } -result {hostname a}
test parse-4 {bang resets parent} -body { lindex [::nc::parse "line vty 0 4\n!\n transport input ssh\n"] 1 2 } -result {}
test host-1 {hostname} -body { ::nc::hostname [::nc::parse "hostname core-1\n"] } -result core-1
test host-2 {missing hostname} -body { ::nc::hostname [::nc::parse "ip ssh version 2\n"] } -result device

test clean-1 {hardened config has no findings} -body { rules "$base$vtyok" } -result {}
test nc001-1 {transport all} -body { has "$base\nline vty 0 4\n access-class A in\n transport input all\n" NC001 high } -result 1
test nc001-2 {transport telnet} -body { has "$base\nline vty 0 4\n access-class A in\n transport input telnet\n" NC001 high } -result 1
test nc001-3 {telnet and ssh} -body { has "$base\nline vty 0 4\n access-class A in\n transport input ssh telnet\n" NC001 high } -result 1
test nc001-4 {no transport line} -body { has "$base\nline vty 0 4\n access-class A in\n" NC001 high } -result 1
test nc001-5 {ssh only is fine} -body { has "$base$vtyok" NC001 high } -result 0
test nc001-6 {two vty blocks, one bad} -body { count "$base$vtyok\nline vty 5 15\n access-class A in\n transport input telnet\n" NC001 } -result 1
test nc002-1 {enable password} -body { has "$base\nenable password foo\n" NC002 high } -result 1
test nc002-2 {enable secret is not enable password} -body { has "$base\nenable secret 9 xyz\n" NC002 high } -result 0
test nc003-1 {public} -body { has "$base\nsnmp-server community public RO\n" NC003 high } -result 1
test nc003-2 {private case-insensitive} -body { has "$base\nsnmp-server community PRIVATE RW\n" NC003 high } -result 1
test nc003-3 {rw custom} -body { has "$base\nsnmp-server community x9f3 RW\n" NC003 high } -result 1
test nc003-4 {ro custom is fine} -body { has "$base\nsnmp-server community x9f3 RO\n" NC003 high } -result 0
test nc004-1 {user password} -body { has "$base\nusername a password 7 0822455D0A16\n" NC004 high } -result 1
test nc004-2 {user with privilege} -body { has "$base\nusername a privilege 15 password 0 x\n" NC004 high } -result 1
test nc004-3 {user secret is fine} -body { has "$base\nusername a secret 9 abc\n" NC004 high } -result 0
test nc005-1 {default password} -body { has "$base\nline con 0\n password cisco\n" NC005 high } -result 1
test nc005-2 {default password typed 7} -body { has "$base\nline con 0\n password 0 admin\n" NC005 high } -result 1
test nc005-3 {strong password not flagged} -body { has "$base\nline con 0\n password Zk8!qv2xLm\n" NC005 high } -result 0
test nc005-4 {value is never printed} -body {
    set out ""; foreach f [::nc::audit "$base\nline con 0\n password cisco\n"] { append out $f }
    string match *cisco* $out
} -result 0
test nc006-1 {enable secret 5} -body { has "$base\nenable secret 5 \$1\$abc\$def\n" NC006 medium } -result 1
test nc006-2 {user secret 5} -body { has "$base\nusername a secret 5 \$1\$abc\n" NC006 medium } -result 1
test nc006-3 {type 9 is fine} -body { has "$base\nenable secret 9 \$9\$abc\n" NC006 medium } -result 0
test nc007-1 {http server} -body { has "$base\nip http server\n" NC007 medium } -result 1
test nc007-2 {no http server} -body { has "$base\nno ip http server\n" NC007 medium } -result 0
test nc008-1 {vty without access-class} -body { has "$base\nline vty 0 4\n transport input ssh\n" NC008 medium } -result 1
test nc008-2 {with access-class} -body { has "$base$vtyok" NC008 medium } -result 0
test nc009-1 {no syslog} -body { has "hostname a\n" NC009 medium } -result 1
test nc009-2 {syslog present} -body { has "$base" NC009 medium } -result 0
test nc010-1 {no ssh v2} -body { has "hostname a\n" NC010 medium } -result 1
test nc010-2 {ssh v2} -body { has $base NC010 medium } -result 0
test nc011-1 {line password w/o encryption} -body { has "$base\nline con 0\n password Zk8!qv2xLm\n" NC011 medium } -result 1
test nc011-2 {with encryption} -body { has "$base\nservice password-encryption\nline con 0\n password Zk8!qv2xLm\n" NC011 medium } -result 0
test nc012-1 {no ntp, banner, source-route} -body { count "hostname a\n" NC012 } -result 3
test nc012-2 {all present} -body { count $base NC012 } -result 0

test sort-1 {high before medium, lines numeric} -body {
    set s [::nc::sort [list {medium R2 a:line 3 m} {high R1 {a:line 10} m} {high R1 {a:line 9} m}]]
    list [lindex $s 0 2] [lindex $s 1 2] [lindex $s 2 0]
} -result {{a:line 9} {a:line 10} medium}
test render-1 {tsv} -body {
    ::nc::render_tsv 1 {{high NC001 {a:line 2} msg}}
} -result "# 1 files, 1 findings\nhigh\tNC001\ta:line 2\tmsg\n"
test render-2 {text} -body { string match "1 files, 1 findings*HIGH*NC001 a:line 2*" [::nc::render_text 1 {{high NC001 {a:line 2} msg}}] } -result 1

proc cli {args} {
    global root
    set code [catch {exec [file join $root bin netconf-audit] {*}$args 2>@1} out opts]
    if {$code == 0} { return 0 }
    return [lindex [dict get $opts -errorcode] end]
}
test cli-1 {ok} -body { cli $root/examples/configs } -result 0
test cli-2 {fail-on high} -body { cli $root/examples/configs --fail-on high } -result 1
test cli-3 {fail-on medium on clean file} -body { cli $root/examples/configs/sw1.cfg --fail-on medium } -result 0
test cli-4 {missing path} -body { cli /no/such/path } -result 2
test cli-5 {no args} -body { cli } -result 2
test cli-6 {bad flag} -body { cli $root/examples/configs --bogus } -result 2
test cli-7 {bad fail-on} -body { cli $root/examples/configs --fail-on nope } -result 2

cleanupTests
if {$::tcltest::numTests(Failed) > 0} { exit 1 }
