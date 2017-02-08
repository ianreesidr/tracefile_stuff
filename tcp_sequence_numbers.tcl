#!/bin/sh
#\
exec tclsh "$0" ${1+ "$@"}
#instructions above apply to executing on Linux systems
#do 'dos2unix' if this doesnt work
if { [catch {eval exec "/usr/local/bin/tshark -r /mnt/support/data/819866/case_819866-test2.pcap -x | grep 0020" } Output] } {
    puts "$::errorCode"
}

set OutputList [split $Output "\n"]
foreach {Item} $OutputList {
    if {[llength $Item] < 10} {
        continue
    }
    set SeqNum [lrange $Item 7 10]
    set result [join $SeqNum ""]
    #set result "0x$result"
    puts [expr 0x$result]
    #scan $result %x decimal
    #puts $decimal
}

