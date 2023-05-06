module CrystalPE
    
    class SectionHeader 
        property name                               : Bytes? # QWORD
        property misc                               : Bytes? # DWORD # this is either PhysicalAddress or VirtualSize
        property virtual_address                    : Bytes? # DWORD
        property size_of_raw_data                   : Bytes? # DWORD
        property pointer_to_raw_data                : Bytes? # DWORD
        property pointer_to_line_numbers            : Bytes? # DWORD
        property number_of_relocations              : Bytes? # WORD
        property number_of_linenumber               : Bytes? # WORD
        property characteristics                    : Bytes? # DWORD


        def raw_bytes() 
            io = IO::Memory.new() 
            io.write( name                               .not_nil! )
            io.write( misc                               .not_nil! )
            io.write( virtual_address                    .not_nil! )
            io.write( size_of_raw_data                   .not_nil! )
            io.write( pointer_to_raw_data                .not_nil! )
            io.write( pointer_to_line_numbers            .not_nil! )
            io.write( number_of_relocations              .not_nil! )
            io.write( number_of_linenumber               .not_nil! )
            io.write( characteristics                    .not_nil! )

            return io.to_slice 
        end 
    end
end