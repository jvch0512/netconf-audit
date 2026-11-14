source [file join [file dirname [info script]] audit.tcl]

proc usage {} {
    puts stderr "usage: netconf-audit PATH \[--tsv\] \[--fail-on high|medium\]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."
    exit 2
}

set path ""; set tsv 0; set fail ""
set i 0
while {$i < [llength $argv]} {
    set a [lindex $argv $i]
    switch -glob -- $a {
        --tsv { set tsv 1 }
        --fail-on {
            incr i
            set v [lindex $argv $i]
            if {$v ni {high medium}} usage
            set fail $v
        }
        -* { usage }
        default { if {$path ne ""} usage; set path $a }
    }
    incr i
}
if {$path eq ""} usage
if {![file exists $path]} { puts stderr "error: no such file or directory: $path"; exit 2 }

if {[file isdirectory $path]} {
    set files {}
    foreach pat {*.cfg *.conf *.txt} { set files [concat $files [glob -nocomplain -directory $path $pat]] }
    set files [lsort -unique $files]
} else {
    set files [list $path]
}
set all {}
foreach f $files {
    set ch [open $f r]; set text [read $ch]; close $ch
    set all [concat $all [::nc::audit $text]]
}
set all [::nc::sort $all]
puts -nonewline [expr {$tsv ? [::nc::render_tsv [llength $files] $all] : [::nc::render_text [llength $files] $all]}]
set code 0
foreach f $all {
    set r [::nc::rank [lindex $f 0]]
    if {$fail eq "high" && $r <= 0} { set code 1 }
    if {$fail eq "medium" && $r <= 1} { set code 1 }
}
exit $code
