module CrystalPE
    
    class SectionHeader 
        property name                               : UInt64 = 0 # Bytes? # QWORD
        property misc                               : UInt32 = 0 # Bytes? # DWORD # this is either PhysicalAddress or VirtualSize
        property virtual_address                    : UInt32 = 0 # Bytes? # DWORD
        property size_of_raw_data                   : UInt32 = 0 # Bytes? # DWORD
        property pointer_to_raw_data                : UInt32 = 0 # Bytes? # DWORD
        property pointer_to_relocations             : UInt32 = 0 # Bytes? # DWORD
        property pointer_to_line_numbers            : UInt32 = 0 # Bytes? # DWORD
        property number_of_relocations              : UInt16 = 0 # Bytes? # WORD
        property number_of_linenumber               : UInt16 = 0 # Bytes? # WORD
        property characteristics                    : UInt32 = 0 # Bytes? # DWORD


        def raw_bytes() 
            io = IO::Memory.new() 
            # io.write( name                               .not_nil! )
            # io.write( misc                               .not_nil! )
            # io.write( virtual_address                    .not_nil! )
            # io.write( size_of_raw_data                   .not_nil! )
            # io.write( pointer_to_raw_data                .not_nil! )
            # io.write( pointer_to_line_numbers            .not_nil! )
            # io.write( number_of_relocations              .not_nil! )
            # io.write( number_of_linenumber               .not_nil! )
            # io.write( characteristics                    .not_nil! )
            IO::ByteFormat::LittleEndian.encode( name                      , io ) 
            IO::ByteFormat::LittleEndian.encode( misc                      , io ) 
            IO::ByteFormat::LittleEndian.encode( virtual_address           , io ) 
            IO::ByteFormat::LittleEndian.encode( size_of_raw_data          , io ) 
            IO::ByteFormat::LittleEndian.encode( pointer_to_raw_data       , io ) 
            IO::ByteFormat::LittleEndian.encode( pointer_to_relocations    , io ) 
            IO::ByteFormat::LittleEndian.encode( pointer_to_line_numbers   , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_relocations     , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_linenumber      , io ) 
            IO::ByteFormat::LittleEndian.encode( characteristics           , io ) 
            return io.to_slice 
        end 

        def name_as_string() : String 
            return String.new(name.unsafe_as(StaticArray(UInt8, 8 )).to_slice)
        end 
    end
end