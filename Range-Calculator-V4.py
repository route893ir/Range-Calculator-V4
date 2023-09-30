
# pip install requests 

import os
import csv
import sys
import ipaddress
import requests

DerakCDNIPv4RangesURL = "https://api.derak.cloud/public/ipv4"
ArvanCloudIPv4RangesURL = "https://www.arvancloud.ir/en/ips.txt"

DerakIPv4Ranges = requests.get( DerakCDNIPv4RangesURL ).text.split( "\n" )
ArvanIPv4Ranges = requests.get( ArvanCloudIPv4RangesURL ).text.split( "\n" )

CurrentDirectoryFiles = os.listdir()

DBIPCSVFileName = ""

for FileName in CurrentDirectoryFiles :
    if FileName.endswith( ".csv" ):
        DBIPCSVFileName = FileName

if DBIPCSVFileName == "" :
    print()
    sys.exit( " DB IP CSV File Not Found ! \n" )

OVPNClientConfigFileName = ""

for FileName in CurrentDirectoryFiles :
    if FileName.endswith( ".ovpn" ):
        OVPNClientConfigFileName = FileName

if OVPNClientConfigFileName == "" :
    print()
    sys.exit( " OpenVPN Client Config File Not Found ! \n" )

IPv4ExcludedRanges = []
IPv6ExcludedRanges = []
IPv6RemainingSeqs = []

IPv4Seqs = []
IPv6Seqs = []

IPv4Seqs.append(
    [ "169.254.0.0" , "169.254.255.255" ]
)

IPv4Seqs.append(
    [ "192.168.0.0" , "192.168.255.255" ]
)

IPv4Seqs.append(
    [ "172.16.0.0" , "172.31.255.255" ]
)

IPv4Seqs.append(
    [ "10.0.0.0" , "10.255.255.255" ]
)


IPv6Seqs.append(
    [ "fc00::" , "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ]
)

IPv6Seqs.append(
    [ "ff00:0000:0000:0000:0000:0000:0000:0000" , "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ]
)

IPv6Seqs.append(
    [ "fe80:0000:0000:0000:0000:0000:0000:0000" , "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ]
)

with open( DBIPCSVFileName ) as DBIPCSVFileObj :
    CSVReader = csv.reader( DBIPCSVFileObj , delimiter = "," )
    for CSVRow in CSVReader :
        Country = CSVRow[ 2 ]
        IPSeq = CSVRow[ 0 : 2 ]
        if Country == "IR" :
            if ":" not in CSVRow[ 0 ] :
                IPv4Seqs.append( IPSeq )
            else :
                IPv6Seqs.append( IPSeq )

ClassXSeqs = []
ClassASeqs = []
ClassBSeqs = []
ClassCSeqs = []

for IPv4Seq in IPv4Seqs :

    StringSeqStart = IPv4Seq[ 0 ].split( "." )
    SeqStart = []
    for StringElement in StringSeqStart :
        SeqStart.append( int( StringElement ) )

    StringSeqEnd = IPv4Seq[ 1 ].split( "." )
    SeqEnd = []
    for StringElement in StringSeqEnd :
        SeqEnd.append( int( StringElement ) )

    if SeqStart[ 0 ] != SeqEnd[ 0 ] :
        ClassXSeqs.append( [ SeqStart , SeqEnd ] )
    else :
        if SeqStart[ 1 ] != SeqEnd[ 1 ] :
            ClassASeqs.append( [ SeqStart , SeqEnd ] )
        else :
            if SeqStart[ 2 ] != SeqEnd[ 2 ] :
                ClassBSeqs.append( [ SeqStart , SeqEnd ] )
            else :
                ClassCSeqs.append( [ SeqStart , SeqEnd ] )

Blocks = [ 1 , 2 , 4 , 8 , 16 , 32 , 64 , 128 ]

ClassCCIDRs = [ "32" , "31" , "30" , "29" , "28" , "27" , "26" , "25" ]

ClassCRanges = []

def ClassC( ClassCSeq ) :
    StringClassCSeqStart = []
    for IntElement in ClassCSeq[ 0 ] :
        StringClassCSeqStart.append( str( IntElement ) )
    if ClassCSeq[ 0 ] == ClassCSeq[ 1 ] :
        ClassCRanges.append( ".".join( StringClassCSeqStart ) + "/32" )
    else :
        ClassCSeqStart = ClassCSeq[ 0 ][ 3 ]
        ClassCSeqEnd = ClassCSeq[ 1 ][ 3 ]
        if ClassCSeqStart == 0 and ClassCSeqEnd == 255 :
            ClassCRanges.append( ".".join( StringClassCSeqStart ) + "/24" )
        else :
            ClassCPrefix = ( "." ).join( StringClassCSeqStart[ 0 : 3 ] ) + "."
            while ClassCSeqStart <= ClassCSeqEnd :
                ClassCDistance = ( ClassCSeqEnd - ClassCSeqStart ) + 1

                ClassCBlock = 1
                for Block in Blocks :
                    NextBlock = Block * 2
                    if ClassCSeqStart % NextBlock != 0 or NextBlock > ClassCDistance :
                        ClassCBlock = Block
                        break

                ClassCCIDR = ClassCCIDRs[ Blocks.index( ClassCBlock ) ]
                ClassCRanges.append( ClassCPrefix + str( ClassCSeqStart ) + "/" + ClassCCIDR )
                ClassCSeqStart = ClassCSeqStart + ClassCBlock

                
for ClassCSeq in ClassCSeqs :
    ClassC( ClassCSeq )

ClassBCIDRs = [ "24" , "23" , "22" , "21" , "20" , "19" , "18" , "17" ]

ClassBRanges = []

def ClassB( ClassBSeq ) :
    StringClassBSeqStart = []
    for IntElement in ClassBSeq[ 0 ] :
        StringClassBSeqStart.append( str( IntElement ) )
    ClassBSeqStart = ClassBSeq[ 0 ][ 2 ]
    ClassBSeqEnd = ClassBSeq[ 1 ][ 2 ]
    ClassCSeqStart = ClassBSeq[ 0 ][ 3 ]
    ClassCSeqEnd = ClassBSeq[ 1 ][ 3 ]
    if ( ClassBSeqStart == ClassCSeqStart == 0 ) and ( ClassBSeqEnd == ClassCSeqEnd == 255 ) :
        ClassBRanges.append( ( "." ).join( StringClassBSeqStart ) + "/16" )
    else :
        if ClassCSeqStart != 0 :
            ClassCSubSeqStart = ClassBSeq[ 0 ]
            ClassC( [ ClassCSubSeqStart , [ ClassCSubSeqStart[ 0 ] , ClassCSubSeqStart[ 1 ] , ClassCSubSeqStart[ 2 ] , 255 ] ] )
            ClassBSeqStart = ClassBSeqStart + 1

        if ClassCSeqEnd != 255 :
            ClassCSubSeqEnd = ClassBSeq[ 1 ]
            ClassC( [ [ ClassCSubSeqEnd[ 0 ] , ClassCSubSeqEnd[ 1 ] , ClassCSubSeqEnd[ 2 ] , 0 ] , ClassCSubSeqEnd ] )
            ClassBSeqEnd = ClassBSeqEnd - 1

        ClassBPrefix = ( "." ).join( StringClassBSeqStart[ 0 : 2 ] ) + "."

        while ClassBSeqStart <= ClassBSeqEnd :

            ClassBDistance = ( ClassBSeqEnd - ClassBSeqStart ) + 1

            ClassBBlock = 1
            for Block in Blocks :
                NextBlock = Block * 2
                if ClassBSeqStart % NextBlock != 0 or NextBlock > ClassBDistance :
                    ClassBBlock = Block
                    break

            ClassBCIDR = ClassBCIDRs[ Blocks.index( ClassBBlock ) ]
            ClassBRanges.append( ClassBPrefix + str( ClassBSeqStart ) + ".0" + "/" + ClassBCIDR )
            ClassBSeqStart = ClassBSeqStart + ClassBBlock

for ClassBSeq in ClassBSeqs :
    ClassB( ClassBSeq )

ClassACIDRs = [ "16" , "15" , "14" , "13" , "12" , "11" , "10" , "9" ]
ClassARanges = []

def ClassA( ClassASeq ) :

    StringClassASeqStart = []
    for IntElement in ClassASeq[ 0 ] :
        StringClassASeqStart.append( str( IntElement ) )
    
    ClassCSeqStart = ClassASeq[ 0 ][ 3 ]
    ClassCSeqEnd = ClassASeq[ 1 ][ 3 ]
    ClassBSeqStart = ClassASeq[ 0 ][ 2 ]
    ClassBSeqEnd = ClassASeq[ 1 ][ 2 ]
    ClassASeqStart = ClassASeq[ 0 ][ 1 ]
    ClassASeqEnd = ClassASeq[ 1 ][ 1 ]

    if ( ClassASeqStart == ClassBSeqStart == ClassCSeqStart == 0 ) and ( ClassASeqEnd == ClassBSeqEnd == ClassCSeqEnd == 255 ) :
        ClassARanges.append( ( "." ).join( StringClassASeqStart ) + "/8" )
    else :

        if ClassBSeqStart != 0 :
            ClassBSubSeqStart = ClassASeq[ 0 ]

            ClassB( [ ClassBSubSeqStart , [ ClassBSubSeqStart[ 0 ] , ClassBSubSeqStart[ 1 ] , 255 , 255 ] ] )
            ClassASeqStart = ClassASeqStart + 1
        
        if ClassBSeqEnd != 255 :
            ClassBSubSeqEnd = ClassASeq[ 1 ]
            ClassB( [ [ ClassBSubSeqEnd[ 0 ] , ClassBSubSeqEnd[ 1 ] , 0 , 0 ] , ClassBSubSeqEnd ] )
            ClassASeqEnd = ClassASeqEnd - 1
        
        ClassAPrefix = ( "." ).join( StringClassASeqStart[ 0 : 1 ] ) + "."

        while ClassASeqStart <= ClassASeqEnd :

            ClassADistance = ( ClassASeqEnd - ClassASeqStart ) + 1
            ClassABlock = 1

            for Block in Blocks :
                NextBlock = Block * 2
                if ClassASeqStart % NextBlock != 0 or NextBlock > ClassADistance :
                    ClassABlock = Block
                    break
            
            ClassACIDR = ClassACIDRs[ Blocks.index( ClassABlock ) ]
            ClassARanges.append( ClassAPrefix + str( ClassASeqStart ) + ".0.0" + "/" + ClassACIDR )
            ClassASeqStart = ClassASeqStart + ClassABlock

for ClassASeq in ClassASeqs :
    ClassA( ClassASeq )

ClassXCIDRs = [ "7" , "6" , "5" , "4" , "3" , "2" , "1" ]
ClassXRanges = []

def ClassX( ClassXSeq ) :
    
    ClassASeqStart = ClassXSeq[ 0 ][ 1 ]
    ClassASeqEnd = ClassXSeq[ 1 ][ 1 ]
    ClassXSeqStart = ClassXSeq[ 0 ][ 0 ]
    ClassXSeqEnd = ClassXSeq[ 1 ][ 0 ]


    if ClassASeqStart != 0 :
        ClassASubSeqStart = ClassXSeq[ 0 ]
        ClassA( [ ClassASubSeqStart , [ ClassASubSeqStart[ 0 ] , 255 , 255 , 255 ] ] )
        ClassXSeqStart = ClassXSeqStart + 1
        
    if ClassASeqEnd != 255 :
        ClassASubSeqEnd = ClassXSeq[ 1 ]
        ClassA( [ [ ClassASubSeqEnd[ 0 ] , 0 , 0 , 0 ] , ClassASubSeqEnd ] )
        ClassXSeqEnd = ClassXSeqEnd - 1
        

    while ClassXSeqStart <= ClassXSeqEnd :

        ClassXDistance = ( ClassXSeqEnd - ClassXSeqStart ) + 1
        ClassXBlock = 1

        for Block in Blocks :
            NextBlock = Block * 2
            if ClassXSeqStart % NextBlock != 0 or NextBlock > ClassXDistance :
                ClassXBlock = Block
                break
            
        ClassXCIDR = ClassXCIDRs[ Blocks.index( ClassXBlock ) ]
        ClassXRanges.append( str( ClassXSeqStart ) + ".0.0.0" + "/" + ClassXCIDR )
        ClassXSeqStart = ClassXSeqStart + ClassXBlock

for ClassXSeq in ClassXSeqs :
    ClassX( ClassXSeq )

IPv4ExcludedRanges.extend( ClassXRanges )

IPv4ExcludedRanges.extend( ClassARanges )

IPv4ExcludedRanges.extend( ClassBRanges )

IPv4ExcludedRanges.extend( ClassCRanges )

for IPv6Seq in IPv6Seqs :

    IPv6AddressesBoxed = []

    for IPv6Address in IPv6Seq :

        IPv6AddressBoxed = []

        if "::" not in IPv6Address :
            IPv6Address = IPv6Address.split( ":" )

            for IPv6AddressBox in IPv6Address :
                IPv6AddressBoxed.append( IPv6AddressBox )
        else :
            ConsecutiveBoxes = IPv6Address.split( "::" )

            if ConsecutiveBoxes[ 1 ] == "" :

                ConsecutiveBoxes = ( ConsecutiveBoxes[ 0 ] ).split( ":" )
                for ConsecutiveBox in ConsecutiveBoxes :
                    IPv6AddressBoxed.append( ConsecutiveBox )
                while len( IPv6AddressBoxed ) < 8 :
                    IPv6AddressBoxed.append( "0000" )

            else :
                FirstConsecutiveBoxes = ( ConsecutiveBoxes[ 0 ] ).split( ":" )
                SecondConsecutiveBoxes = ( ConsecutiveBoxes[ 1 ] ).split( ":" )
                CompressedBoxes = 8 - ( len( FirstConsecutiveBoxes ) + len( SecondConsecutiveBoxes ) )
                for ConsecutiveBox in FirstConsecutiveBoxes :
                    IPv6AddressBoxed.append( ConsecutiveBox )
                while CompressedBoxes > 0 :
                    IPv6AddressBoxed.append( "0000" )
                    CompressedBoxes = CompressedBoxes - 1
                for ConsecutiveBox in SecondConsecutiveBoxes :
                    IPv6AddressBoxed.append( ConsecutiveBox )
            
        IPv6AddressesBoxed.append( IPv6AddressBoxed )
    
    IPv6AddressesBoxedPadded = []
    for IPv6AddressBoxed in IPv6AddressesBoxed :
        IPv6AddressBoxPadded = []
        for IPv6AddressBox in IPv6AddressBoxed :
            IPv6BoxPadded = IPv6AddressBox
            while len( IPv6BoxPadded ) < 4 :
                IPv6BoxPadded = "0" + IPv6BoxPadded
            IPv6AddressBoxPadded.append( IPv6BoxPadded )
        IPv6AddressesBoxedPadded.append( IPv6AddressBoxPadded )
    
    SeqStart = IPv6AddressesBoxedPadded[ 0 ]
    SeqEnd = IPv6AddressesBoxedPadded[ 1 ]

    if SeqStart == SeqEnd :
        IPv6Range = ":".join( SeqStart ) + "/128"
    else :
        BoxIndex = 0
        NetIDBits = 0
        Calculated = False
        while BoxIndex <= 7 :
            SeqStartBox = SeqStart[ BoxIndex ]
            SeqEndBox = SeqEnd[ BoxIndex ]

            if SeqStartBox != SeqEndBox :

                SeqStartValue = int( "".join( SeqStart[ BoxIndex : ] ) , 16 )
                SeqEndValue = int( "".join( SeqEnd[ BoxIndex : ] ) , 16 )
                Distance = ( SeqEndValue - SeqStartValue ) + 1
                PossibleHostBits = range( ( 128 - NetIDBits ) + 1 , 0 , -1 )
                AvailableHosts = []
                for PossibleHostBit in PossibleHostBits :
                    AvailableHosts.append( pow( 2 , PossibleHostBit ) )
                
                for AvailableHost in AvailableHosts :

                    if Distance == AvailableHost and SeqStartValue % AvailableHost == 0 :
                        HostBits = PossibleHostBits[ AvailableHosts.index( AvailableHost ) ]
                        SubNetBits = 128 - ( NetIDBits + HostBits )
                        IPv6CIDR = NetIDBits + SubNetBits 
                        IPv6ExcludedRanges.append( ":".join( SeqStart ) + "/" + str( IPv6CIDR ) )
                        Calculated = True
                        break
                    
            else :
                NetIDBits = NetIDBits + 16
            if Calculated != True :
                BoxIndex = BoxIndex + 1
            else :
                break

for DerakIPv4Range in DerakIPv4Ranges :
    AlreadyExcluded = False
    for IPv4ExcludedRange in IPv4ExcludedRanges :
        ExcludedRange = ipaddress.ip_network( IPv4ExcludedRange )
        DerakRange = ipaddress.ip_network( DerakIPv4Range )
        if IPv4ExcludedRange == DerakIPv4Range or DerakRange.subnet_of( ExcludedRange ) :
            AlreadyExcluded = True
    if AlreadyExcluded == False :
        IPv4ExcludedRanges.append( DerakIPv4Range )

for ArvanIPv4Range in ArvanIPv4Ranges :
    AlreadyExcluded = False
    for IPv4ExcludedRange in IPv4ExcludedRanges :
        ExcludedRange = ipaddress.ip_network( IPv4ExcludedRange )
        ArvanRange = ipaddress.ip_network( ArvanIPv4Range )
        if IPv4ExcludedRange == ArvanIPv4Range or ArvanRange.subnet_of( ExcludedRange ) :
            AlreadyExcluded = True
    if AlreadyExcluded == False :
        IPv4ExcludedRanges.append( ArvanIPv4Range )

def ReturnCIDR( ExcludedRange ) :
    ExcludedRangeCIDR = int( ( ExcludedRange.split( "/" ) )[ 1 ] )
    return ExcludedRangeCIDR

IPv4ExcludedRanges.sort( key=ReturnCIDR )

IPv6ExcludedRanges.sort( key=ReturnCIDR )

IPv4ExcludedRangesMask = []
for IPv4ExcludedRange in IPv4ExcludedRanges :

    IPv4RangeCIDR = ReturnCIDR( IPv4ExcludedRange )

    if IPv4RangeCIDR == 32 :
        NetMask = [ 255 , 255 , 255 , 255 ]
    else :
        NetMask = []
        NetMaskBytesNumber = int( IPv4RangeCIDR / 8 )
        while NetMaskBytesNumber > 0 :
            NetMask.append( 255 )
            NetMaskBytesNumber = NetMaskBytesNumber - 1
        AvailableSubNetMaskBits = [ 0 , 1 , 2 , 3 , 4 , 5 , 6 , 7 ]
        AvailableSubNetMaskValues = [ 0 , 128 , 192 , 224 , 240 , 248 , 252 , 254 ]
        SubNetMaskBits = IPv4RangeCIDR % 8
        NetMask.append( AvailableSubNetMaskValues[ AvailableSubNetMaskBits.index( SubNetMaskBits ) ] )
        while len( NetMask ) < 4 :
            NetMask.append( 0 )
    NetMaskString = []
    for IntByte in NetMask :
        NetMaskString.append( str( IntByte ) )
    IPv4ExcludedRangesMask.append( ".".join( NetMaskString ) )

OVPNClientConfigFileObj = open( OVPNClientConfigFileName ,"a+" )

VPNExcludedRangesRSCFileObj = open( "Mikrotik-VPN-Excluded-Ranges-" + DBIPCSVFileName[ -9 : -4 ] + ".rsc" ,"w+" )

IPv4ExcludedRangeIndex = 0
for IPv4ExcludedRange in IPv4ExcludedRanges :
    OVPNClientConfigFileObj.write( "route " + ( IPv4ExcludedRange.split( "/" ) )[ 0 ] + " " + IPv4ExcludedRangesMask[ IPv4ExcludedRangeIndex ] + " net_gateway \n" )
    IPv4ExcludedRangeIndex = IPv4ExcludedRangeIndex + 1

OVPNClientConfigFileObj.write( "route-ipv6 " + "::/0" + " \n" )

for IPv4ExcludedRange in IPv4ExcludedRanges :
    VPNExcludedRangesRSCFileObj.write( "/ip firewall address-list add address=" + IPv4ExcludedRange + " list=VPN-Excluded-Ranges" + "\n" )

for IPv6ExcludedRange in IPv6ExcludedRanges :
    VPNExcludedRangesRSCFileObj.write( "/ipv6 firewall address-list add address=" + IPv6ExcludedRange + " list=VPN-Excluded-Ranges" + "\n" )


# route 192.168.1.0 255.255.255.0 net_gateway
# route-ipv6 ::/0

OVPNClientConfigFileObj.close()
VPNExcludedRangesRSCFileObj.close()
