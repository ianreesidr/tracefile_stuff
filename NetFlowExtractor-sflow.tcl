#!/bin/sh
#\
exec tclsh "$0" ${1+ "$@"}
#instructions above apply to executing on Linux systems
#do 'dos2unix' if this doesnt work
###########################
###NetFlowExtractor#####
###########################
# Collects Flow Data from TShark Output or Text File created in tshark and formatted as specified in proc
# readCap and writes it to a CSV file
# Deals with the problem that each NetFlow packet contains multiple flow records
# By sorting the flow records and formatting them as comma separated values
#
# run in this format /usr/bin/tclsh NetFlowExtractor.tcl <input file> <output file> <options>
#
# First parameter is the full path to the pcap file which must contain only NetFlow v5 or NetFlow v9 packets
# note that the fields selected by TShark must be present in all the flow data collected.
# TShark statement will need to be adapted based on Flow Template used
# future release can build the Tshark statement based on the Flow Template found.
#
# Second parameter is the full path to the output file.
# The -d switch in TShark is used to decode as cflow eg -d udp.port==2505,cflow
# note that excel currently supports just over 1 million rows. Any more rows created in
# your .csv file will not be displayed
# in this version: records with no cflow.octets field are skipped. this is because they contain templates and no flow data
# identified by Tshark
# 18th May 2016 modified so that fields that are common such as flow source IP address are populated to each flow record
# this makes the data more useful as this information is not lost when filters or sorts are applied to the spreadsheet.
# 17th Aug 2016 modified
#       1. Separate procedures for processing tshark output or 'raw' pcap file
#       2. Procedure to handle NAT information from PaloAlto firewall NetFlow (where source address is preserved and destination address NATTed)
#       3. Procedure to specify which fields are safe to replicate across all flowsets within a NetFlow packet (deprecates change of 18th May 2016)
#       4. Online help and options switches to specify NetFlow port, Tshark location and NAT data present
#       5. Fix to cope with packets that contain some templates and some flow data which were not being handled correctly
#       6. Fix to parse pcaps twice to read templates (tshark -2 switch)
#       7. Parse a list of all NetFlow fields we want to use (note that cflow.count and cflow.octets are mandatory and their position cannot be changed)
# this version 24/8/16
#  1. added Linux exec so that we can run the command without specifying path (still needs to be placed in /usr/bin and chmod +x to make executable)
#  2. made cflow.count and cflow.octets permanent in list of tshark fields as these fields are used by the code.
# modified to work with old tshark version 1.6 on RockMachines
# remove the '-2' flag to parse twice over the pcap.
#TO DO
# :
#  make check for octets optional field - consider file captureNetFlow-172.20.9.13.pcap which came from a palo alto and tshark is unable to read octects field
#  how to deal with fields such as cflow.fe_passthrough_reason which do not appear in every flowset. currently the flowsets that do not have a value do not get counted
if {0} {
        rename set _set
    proc set {var args} {
       puts [list setting $var $args]
       uplevel _set $var $args
    }
}
#
# Procedure to index values that are to be replicated for all flowsets within a NetFlow packet
proc indexCommonFields {AllFields} {
        set CommonFields {frame.number ip.src cflow.sequence cflow.source_id cflow.unix_secs cflow.sysuptime}
        set CommonFieldsList {}
        foreach {Field} $CommonFields {
                set FieldIndex [lsearch $AllFields $Field]
                lappend CommonFieldsList $FieldIndex
        }
        return $CommonFieldsList
}
#
#
# Procedure to read flows from a Pcap
proc readPcap {cFlows} {
        global port
        global tshark
        global sFlow
        if {$sFlow == 1} {
                set FlowFields {
                        sflow_245.numsamples sflow.flow_sample.sequence_number sflow.flow_sample.input_interface sflow.flow_sample.output_interface eth.dst eth.src  eth.type ip.dsfield ip.flags ip.proto ip.src ip.dst udp.srcport udp.dstport tcp.srcport tcp.dstport sflow_245.header.frame_length frame.number
                }
                set FlowType "sflow"
        } else {
                set FlowFields {
        cflow.count cflow.octets cflow.packets  cflow.inputint  cflow.outputint  cflow.srcaddr  cflow.dstaddr  cflow.protocol  cflow.tos cflow.srcport cflow.dstport  cflow.timestart  cflow.timeend cflow.timedelta cflow.sampler_id  cflow.flow_class  cflow.nexthop  cflow.dstmask  cflow.srcmask  cflow.tcpflags  cflow.direction  cflow.sequence cflow.source_id  ip.src frame.number cflow.unix_secs cflow.sysuptime
                }
                set FlowType "cflow"
        }
        set AllFieldsExtract {}
        foreach {Field} $FlowFields {
                set AllFieldsExtract [concat $AllFieldsExtract  "-e $Field"]
        }
        set cFlows "$tshark -r $cFlows"
        set cFlowArgs "-d udp.port==$port,$FlowType -T fields $AllFieldsExtract -E header=y -E separator=, -E quote=d -E occurrence=a -E aggregator=/s"
        set cFlows [concat $cFlows $cFlowArgs]
        if { [catch {eval exec $cFlows } TsharkOutput] } {
           puts "$::errorCode"
        }
        set fileAsList [split $TsharkOutput \n]
        return $fileAsList
}
#
# Procedure to read flows from a text file generated by tshark (not called from this program)
proc readText {textFile} {
        set TsharkOutput $textFile
        if {[catch {open $TsharkOutput r} fileId]} {
                 error $fileId $::errorInfo $::errorCode
        } else {
                 set fileAsList [split [read -nonewline $fileId] \n]
                 close $fileId
        }
        return $fileAsList
}
#
# Procedure to write the NAT addresses in the correct position #
proc natPos {fileAsList} {
        set NewList {}
        foreach {NetFlowPacket} $fileAsList {
                set NewPacket {}
                set InputList [split $NetFlowPacket ,]
                set SourceNatList [lindex [lindex $InputList 3] 0]
                if {[llength $SourceNatList] > 0} {
                        set DestNatList [lindex [lindex $InputList 5] 0]
                        set SourceIPList [lindex [lindex $InputList 2] 0]
                        set SourceNatListNew {}
                        set DestNatListNew {}
                        ### Assuming Source NAT address is preserved
                        ### Find position of each NAT IP address and create list
                        set Count 0
                        foreach {Item} $SourceIPList {
                                #search for match in SourceNatList
                                set NatIndex [lsearch $SourceNatList $Item]
                                if {$NatIndex == -1} {
                                        lappend SourceNatListNew "N"
                                        lappend DestNatListNew "N"
                                } else {
                                        lappend SourceNatListNew [lindex $SourceIPList $Count]
                                        lappend DestNatListNew [lindex $DestNatList $NatIndex]
                                        set SourceNatList [lreplace $SourceNatList $NatIndex $NatIndex]
                                }
                                incr Count
                        }
                        ### insert New List in place of old
                        set SourceNatListNew \"$SourceNatListNew\"
                        set InputList [lreplace $InputList 3 3 $SourceNatListNew]
                        set DestNatListNew \"$DestNatListNew\"
                        set InputList [lreplace $InputList 5 5 $DestNatListNew]
                        ####
                } else {
                }
                # Rewrite the NetFlow packet to original format
                set NewPacket [join $InputList ,]
                lappend NewList $NewPacket
        }
        return $NewList

}
# Procedure to write the flows to  comma separated values
proc flows2CSV {fileAsList OutputFile} {
                global nat
                global sFlow
                #read the first line which is comma separated headings
                set OutputList {}
                lappend OutputList [lindex $fileAsList 0]
                set HeaderList [split $OutputList ,]
                # get list of common fields that will be replicated for multiple flowsets within one packet
                set CommonFields [indexCommonFields $HeaderList]
                # find the number of fields defined by Tshark command
                set FieldCount [llength $HeaderList]
                #strip off the header. begin at the line that begins with a " mark
                set fileAsList  [lrange $fileAsList 1 [llength $fileAsList]]
                #Remove any TShark error of this type "Running as user "root" and group "root". This could be dangerous."
                # get the last line of fileAsList and check if it includes "Running" then delete it
                set LastLine [lindex $fileAsList [expr {[llength $fileAsList] -1}]]
                if {[string first "Running" $LastLine] != -1} {
                        set fileAsList [lrange $fileAsList 0 [expr {[llength $fileAsList] -2}]]
                }
                # call NAT indexing procedure
                if {$nat == 1} {
                        set fileAsList [natPos $fileAsList]
                }
                #at this point data from each packet is separated by a space. handle each packet of aggregated values separately.
                set PacketCount 0
                set FlowCount 0
                foreach {CflowPacket} $fileAsList {
                #set CflowPacket [lindex $fileAsList 0]
                        # separate the data into a list of lists of aggregated values
                        set SuperList [split $CflowPacket ,]
                        # the first item is the number of flow records in a packet
                        set CflowCount [lindex [lindex $SuperList 0] 0]
                        # commented out check for no octets as I am interested in templates too.
                        # test to see if the packet has no cflow.octets fields. It is a template and does not contain interesting NetFlow records
                        if {[lindex $SuperList 1] == {}} {
                                # go straight to the next packet
                                incr PacketCount
                                continue
                        }
                        # end of commented out section
                        # if flows are SFLOW then use the number of sflow sequence number records to define the the number of flows in a packet
                        if {$sFlow == 1} {
                                set CflowCount [llength  [lindex [lindex $SuperList 1] 0]]
                        }
                        # take the pointed to item in the nth list of aggregated values and append it to a comma separated string
                        # then append the string to a list for writing to file
                        set Pointer 0
                        # loop through the pdu's
                        while {$Pointer < $CflowCount} {
                                set CommaString {}
                                set CommaList {}
                                set SubList {}
                                set FieldIndex 0
                                # select the value identified by pointer in each cell and append to CommaList
                                foreach {SubString} $SuperList {
                                        # remove the quotes
                                        set SubList [lindex $SubString 0]
                                        # for sflows we need to discard the external header information
                                        # increment FieldIndex by 1 if length SubList > CflowCount
                                        if {[llength $SubList] > $CflowCount} {
                                                set Item [lindex $SubList [expr ($Pointer+1)]]
                                        } else {
                                                set Item [lindex $SubList $Pointer]
                                        }
                                        # catch instance when the Tshark field is not present in the flow record
                                        if {$Item == {} && [lsearch $CommonFields $FieldIndex] > -1} {
                                                # if an item is blank set it to the first item in the list
                                                # only if it has been flagged as a common field
                                                # the value is common to all flow records in the cflow packet
                                                # eg: frame number or cflow sequence or flow source ip address
                                                set Item [lindex $SubList 0]
                                        } elseif {$Item == {}}  {
                                                set Item "-"
                                        }
                                        lappend CommaList $Item
                                        incr FieldIndex
                                }
                                # add Commas to CommaList
                                set CommaString [join $CommaList ,]
                                # sometimes CflowCount includes flowsets that contain templates or extra info that we don't tabulate
                                # check if there are no numbers in which case do not add CommaString to OutputList
                                if {![regexp {[0-9]} $CommaString]} {
                                        incr Pointer
                                        continue
                                }
                                # Otherwise add the row
                                lappend OutputList $CommaString
                                incr Pointer
                                incr FlowCount
                        }
                        incr PacketCount
                }
                ### write to the new file
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
                puts "$PacketCount packets analysed"
                puts "$FlowCount flows written to file $OutputFile"
}
if {0} {
        set InFile "~/cflows.pcap"
        set OutFile "~/F2CSVOutput.csv"
        if {[llength $argv] == 2} {
                set InFile [lindex $argv 0]
                set OutFile [lindex $argv 1]
        } elseif {[llength $argv] == 1} {
                set InFile [lindex $argv 0]
                puts "No output filename provided. Flows2CSV.tcl will attempt to write to ~/F2CSVOutput.csv"
        } else {
                puts "No input or output filename provided. Flows2CSV.tcl will attempt to  read from ~/cflows.pcap and write to ~/F2CSVOutput.csv"
        }
}
set arglen [llength $argv]
set index 0
set nat 0
set sFlow 0
set port 2505
set tshark "/usr/sbin/tshark"
set helptext "\n\nNetFlowExtractor  -- Takes a pcap file containing NetFlow flowsets or a text file generated by Tshark and outputs a csv file of flow sets for analysis in a spreadsheet\n\nUsage: \n/path/to/tclsh NetFlowExtractor.tcl <options> Inputfile.txt (or Inputfile.pcap) Outputfile.csv \n\nFor Inputfile.txt use a text file which has been generated by tshark \nFor Inputfile.pcap file use a pcap or pcapng file \nFor Outputfile.csv always specify csv file extension\n\nOptions:\n-p -- set NetFlow port to decode (default 2505)\n-n -- NAT data in file (use tshark format specified below)\n-t -- set tshark excutable path (default is /usr/sbin/tshark)\n-h -- help\n\nNote on NAT data format. Tshark will need to be 1.4.0 or above (reference: https://www.wireshark.org/docs/dfref/c/cflow.html)\n\nUse the following format:\n\ntshark -r capturefile.pcap -d udp.port==2505,cflow -T fields -e cflow.count -e cflow.octets -e cflow.srcaddr -e cflow.post_natsource_ipv4_address -e cflow.dstaddr -e cflow.post_natdestination_ipv4_address -e frame.number -E header=y -E separator=, -E quote=d -E occurrence=a -E aggregator=/s >outputfile.txt"
if {0} {
while {$index < $arglen} {
        set arg [lindex $argv $index]
        switch -glob $arg {
                *.txt {
                        set InFile [readText $arg]
                }
                *.pcap* {
                        set InFile [readPcap $arg]
                }
                *.csv {
                        set OutFile $arg
                }
                /p      {
                        set port [lindex $argv [expr ($index + 1)]]
                }
                /n      {
                        set nat 1
                }
                /s      {
                        set sFlow 1
                }
                /t      {
                        set tshark [lindex $argv [expr ($index + 1)]]
                }
                /h      {
                        puts $helptext
                        exit
                }
                default {
                }

        }
        incr index
}
}
# argv is set by the Tcl shells
set state flag
foreach arg $argv {
        switch -- $state {
                flag {
                        switch -glob -- $arg {
                                -n*             {set nat 1}
                                -s*             {set sFlow 1}
                                -h*             {puts $helptext
                                                exit}
                                -p*             {set state port}
                                -t*             {set state tshark}
                                *.pcap*         {set InFile [readPcap $arg]}
                                *.txt           {set InFile [readText $arg]}
                                *.csv           {set OutFile $arg}
                                default         {puts "unknown flag $arg"
                                                exit}
                        }
                }
                port {
                        set port $arg
                        set state flag
                }
                tshark {
                        set tshark $arg
                        set state flag
                }
        }
}

# catch if no input file or output file is specified
if {![info exists InFile] || ![info exists OutFile]} {
        puts $helptext
        exit
}
# call flows2CSV
if {[catch {flows2CSV $InFile $OutFile} Result]} {
    error $Result $::errorInfo $::errorCode
}
