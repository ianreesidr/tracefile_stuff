#!/usr/root/tcl/tclsh
###########################
###Tshark Server Extension Names#####
###########################
# Tshark Filters pcap for client hello field ssl.handshake.extensions_server_name
# the list of server names is sorted and duplicates are removed.

# this routine debugs variable values to the console it is currently disabled
if {0} {
	rename set _set
    proc set {var args} {
       puts [list setting $var $args]
       uplevel _set $var $args
    }
}
#
#
set tshark "/usr/sbin/tshark"
#
#
proc getServerNames {tshark pcapFile OutputFile} {
	set pcapFile "$tshark -r $pcapFile"
	set pcapArgs "-T fields -e ssl.handshake.extensions_server_name"
	set AllServerNames [concat $pcapFile $pcapArgs]
	if { [catch {eval exec $AllServerNames } TsharkOutput] } {
 	   puts "TShark Errors: $::errorCode"
	}
	set FileAsList [split $TsharkOutput \n]
	#Remove any TShark error of this type "Running as user "root" and group "root". This could be dangerous."
	# get the last line of FileAsList and check if it includes "Running" then delete it
	set LastLine [lindex $FileAsList [expr {[llength $FileAsList] -1}]]
	if {[string first "Running" $LastLine] != -1} {
		set FileAsList [lrange $FileAsList 0 [expr {[llength $FileAsList] -2}]]
	}
	# command to create unique sorted list
	set OutputList [lsort -unique $FileAsList]
	#
	### write to the new file
	#	
	# write the new values in List1 to File1
	if {[catch {open $OutputFile w} fileId]} {
		error $fileId $::errorInfo $::errorCode
	} else { 
		foreach {Item} $OutputList {
			puts $fileId $Item
		}
	}
	close $fileId
	#
	# output text
	puts "SSL Server Names written to file $OutputFile"
}

set InFile "~/RawServerList.txt"
set OutFile ~/ServerList.txt"
if {[llength $argv] == 2} {
	set InFile [lindex $argv 0]
	set OutFile [lindex $argv 1]
} elseif {[llength $argv] == 1} {
	set InFile [lindex $argv 0]
	puts "No output filename provided. ServerExtensionNames.tcl will attempt to write to ~/ServerList.txt"
} else {
	puts "No input or output filename provided. ServerExtensionNames.tcl will attempt to  read from ~/RawServerList.txt and write to ~/ServerList.txt"
}
if {[file exists $InFile]} {
	# call getServerNames
	if {[catch {getServerNames $tshark $InFile $OutFile} Result]} {
        error $Result $::errorInfo $::errorCode
	}
}