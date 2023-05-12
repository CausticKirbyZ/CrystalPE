module CrystalPE
    # dos header is a 64 Byte header
    class DOSHeader

        property e_magic    : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Magic number
        property e_cblp     : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Bytes on last page of file
        property e_cp       : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Pages in file
        property e_crlc     : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Relocations
        property e_cparhdr  : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Size of header in paragraphs
        property e_minalloc : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Minimum extra paragraphs needed
        property e_maxalloc : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Maximum extra paragraphs needed
        property e_ss       : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Initial (relative) SS value
        property e_sp       : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Initial SP value
        property e_csum     : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Checksum
        property e_ip       : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Initial IP value
        property e_cs       : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Initial (relative) CS value
        property e_lfarlc   : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # File address of relocation table
        property e_ovno     : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # Overlay number
        property e_res      : Bytes = Bytes[0,0,0,0, 0,0,0,0]                           # 4 Reserved words
        property e_oemid    : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # OEM identifier (for e_oeminfo)
        property e_oeminfo  : UInt16 = 0 # Bytes? # = Bytes[0x0]                        # OEM information; e_oemid specific
        property e_res2     : Bytes  = Bytes[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]   # 10 Reserved words
        property e_lfanew   : UInt32 = 0 # Bytes? # = Bytes[0x0]                        # File address of new exe header



        # this function will return the raw bytes as it would be in the file on disk. 
        # in little endian format 
        def raw_bytes() : Bytes 
            io = IO::Memory.new
            
            
            # io.write(e_magic    .not_nil!)
            # io.write(e_cblp     .not_nil!)
            # io.write(e_cp       .not_nil!)
            # io.write(e_crlc     .not_nil!)
            # io.write(e_cparhdr  .not_nil!)
            # io.write(e_minalloc .not_nil!)
            # io.write(e_maxalloc .not_nil!)
            # io.write(e_ss       .not_nil!)
            # io.write(e_sp       .not_nil!)
            # io.write(e_csum     .not_nil!)
            # io.write(e_ip       .not_nil!)
            # io.write(e_cs       .not_nil!)
            # io.write(e_lfarlc   .not_nil!)
            # io.write(e_ovno     .not_nil!)
            # io.write(e_res      .not_nil!)
            # io.write(e_oemid    .not_nil!)
            # io.write(e_oeminfo  .not_nil!)
            # io.write(e_res2     .not_nil!)
            # io.write(e_lfanew   .not_nil!)
            IO::ByteFormat::LittleEndian.encode( e_magic    , io )
            IO::ByteFormat::LittleEndian.encode( e_cblp     , io )
            IO::ByteFormat::LittleEndian.encode( e_cp       , io )
            IO::ByteFormat::LittleEndian.encode( e_crlc     , io )
            IO::ByteFormat::LittleEndian.encode( e_cparhdr  , io )
            IO::ByteFormat::LittleEndian.encode( e_minalloc , io )
            IO::ByteFormat::LittleEndian.encode( e_maxalloc , io )
            IO::ByteFormat::LittleEndian.encode( e_ss       , io )
            IO::ByteFormat::LittleEndian.encode( e_sp       , io )
            IO::ByteFormat::LittleEndian.encode( e_csum     , io )
            IO::ByteFormat::LittleEndian.encode( e_ip       , io )
            IO::ByteFormat::LittleEndian.encode( e_cs       , io )
            IO::ByteFormat::LittleEndian.encode( e_lfarlc   , io )
            IO::ByteFormat::LittleEndian.encode( e_ovno     , io )
            io.write(e_res ) # byte chunk here 
            IO::ByteFormat::LittleEndian.encode( e_oemid    , io )
            IO::ByteFormat::LittleEndian.encode( e_oeminfo  , io )
            io.write(e_res2 ) # byte chunk here 
            IO::ByteFormat::LittleEndian.encode(e_lfanew, io )



            return io.to_slice             
        end
    end
end 