module CrystalPE
    # dos header is a 64 Byte header
    class DOSHeader

        # # each _e... is the actual Byte sequence as it is represented in the file 
        # property _e_magic    : Bytes? # = Bytes[0x0]               # Magic number
        # property _e_cblp     : Bytes? # = Bytes[0x0]               # Bytes on last page of file
        # property _e_cp       : Bytes? # = Bytes[0x0]               # Pages in file
        # property _e_crlc     : Bytes? # = Bytes[0x0]               # Relocations
        # property _e_cparhdr  : Bytes? # = Bytes[0x0]               # Size of header in paragraphs
        # property _e_minalloc : Bytes? # = Bytes[0x0]               # Minimum extra paragraphs needed
        # property _e_maxalloc : Bytes? # = Bytes[0x0]               # Maximum extra paragraphs needed
        # property _e_ss       : Bytes? # = Bytes[0x0]               # Initial (relative) SS value
        # property _e_sp       : Bytes? # = Bytes[0x0]               # Initial SP value
        # property _e_csum     : Bytes? # = Bytes[0x0]               # Checksum
        # property _e_ip       : Bytes? # = Bytes[0x0]               # Initial IP value
        # property _e_cs       : Bytes? # = Bytes[0x0]               # Initial (relative) CS value
        # property _e_lfarlc   : Bytes? # = Bytes[0x0]               # File address of relocation table
        # property _e_ovno     : Bytes? # = Bytes[0x0]               # Overlay number
        # property _e_res      : Bytes? # = Bytes[0x0]               # Reserved words
        # property _e_oemid    : Bytes? # = Bytes[0x0]               # OEM identifier (for e_oeminfo)
        # property _e_oeminfo  : Bytes? # = Bytes[0x0]               # OEM information; e_oemid specific
        # property _e_res2     : Bytes? # = Bytes[0x0]               # Reserved words
        # property _e_lfanew   : Bytes? # = Bytes[0x0]               # File address of new exe header

        # these show become the usable version where its the numeric value 
        property e_magic    : Bytes? # = Bytes[0x0]               # Magic number
        property e_cblp     : Bytes? # = Bytes[0x0]               # Bytes on last page of file
        property e_cp       : Bytes? # = Bytes[0x0]               # Pages in file
        property e_crlc     : Bytes? # = Bytes[0x0]               # Relocations
        property e_cparhdr  : Bytes? # = Bytes[0x0]               # Size of header in paragraphs
        property e_minalloc : Bytes? # = Bytes[0x0]               # Minimum extra paragraphs needed
        property e_maxalloc : Bytes? # = Bytes[0x0]               # Maximum extra paragraphs needed
        property e_ss       : Bytes? # = Bytes[0x0]               # Initial (relative) SS value
        property e_sp       : Bytes? # = Bytes[0x0]               # Initial SP value
        property e_csum     : Bytes? # = Bytes[0x0]               # Checksum
        property e_ip       : Bytes? # = Bytes[0x0]               # Initial IP value
        property e_cs       : Bytes? # = Bytes[0x0]               # Initial (relative) CS value
        property e_lfarlc   : Bytes? # = Bytes[0x0]               # File address of relocation table
        property e_ovno     : Bytes? # = Bytes[0x0]               # Overlay number
        property e_res      : Bytes? # = Bytes[0x0]               # Reserved words
        property e_oemid    : Bytes? # = Bytes[0x0]               # OEM identifier (for e_oeminfo)
        property e_oeminfo  : Bytes? # = Bytes[0x0]               # OEM information; e_oemid specific
        property e_res2     : Bytes? # = Bytes[0x0]               # Reserved words
        property e_lfanew   : Bytes? # = Bytes[0x0]               # File address of new exe header



        # this function will return the raw bytes as it would be in the file on disk. 
        # in little endian format 
        def raw_bytes() : Bytes 
            io = IO::Memory.new            
            io.write(e_magic    .not_nil!)
            io.write(e_cblp     .not_nil!)
            io.write(e_cp       .not_nil!)
            io.write(e_crlc     .not_nil!)
            io.write(e_cparhdr  .not_nil!)
            io.write(e_minalloc .not_nil!)
            io.write(e_maxalloc .not_nil!)
            io.write(e_ss       .not_nil!)
            io.write(e_sp       .not_nil!)
            io.write(e_csum     .not_nil!)
            io.write(e_ip       .not_nil!)
            io.write(e_cs       .not_nil!)
            io.write(e_lfarlc   .not_nil!)
            io.write(e_ovno     .not_nil!)
            io.write(e_res      .not_nil!)
            io.write(e_oemid    .not_nil!)
            io.write(e_oeminfo  .not_nil!)
            io.write(e_res2     .not_nil!)
            io.write(e_lfanew   .not_nil!)
            return io.to_slice             
        end
    end
end 