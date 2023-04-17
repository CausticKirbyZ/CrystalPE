module CrystalPE

    # dos header is a 64 Byte header
    struct DOS_Header
        property e_magic    : Bytes                # Magic number
        property e_cblp     : Bytes                # Bytes on last page of file
        property e_cp       : Bytes                # Pages in file
        property e_crlc     : Bytes                # Relocations
        property e_cparhdr  : Bytes                # Size of header in paragraphs
        property e_minalloc : Bytes                # Minimum extra paragraphs needed
        property e_maxalloc : Bytes                # Maximum extra paragraphs needed
        property e_ss       : Bytes                # Initial (relative) SS value
        property e_sp       : Bytes                # Initial SP value
        property e_csum     : Bytes                # Checksum
        property e_ip       : Bytes                # Initial IP value
        property e_cs       : Bytes                # Initial (relative) CS value
        property e_lfarlc   : Bytes                # File address of relocation table
        property e_ovno     : Bytes                # Overlay number
        property e_res      : Bytes                # Reserved words
        property e_oemid    : Bytes                # OEM identifier (for e_oeminfo)
        property e_oeminfo  : Bytes                # OEM information; e_oemid specific
        property e_res2     : Bytes                # Reserved words
        property e_lfanew   : Bytes                # File address of new exe header




        def initialize
        end

    end

end