
module CrystalPE  

    class NT_Headers
        property signature                          : Bytes? 
        property file_headers                       : NTFileHeaders =  NTFileHeaders.new()
        property optional_headers                   : NTOptionalHeaders = NTOptionalHeaders.new()


        # returns the raw byes as it would in the file. 
        # used for writing this part to a file
        def raw_bytes() : Bytes 
            io = IO::Memory.new            
            io.write( signature.not_nil! )
            io.write( file_headers.raw_bytes() )
            io.write( optional_headers.raw_bytes() )
            return io.to_slice            
        end 

    end

    class NTFileHeaders
        property machine                            : Bytes? 
        property number_of_sections                 : Bytes? 
        property time_date_stamp                    : Bytes? 
        property pointer_to_symbol_table            : Bytes? 
        property number_of_symbols                  : Bytes? 
        property size_of_optional_header            : Bytes? 
        property characteristics                    : Bytes? 

        def raw_bytes() : Bytes 
            io = IO::Memory.new            
            io.write( machine.not_nil! )
            io.write( number_of_sections         .not_nil!)
            io.write( time_date_stamp            .not_nil!)
            io.write( pointer_to_symbol_table    .not_nil!)
            io.write( number_of_symbols          .not_nil!)
            io.write( size_of_optional_header    .not_nil!)
            io.write( characteristics            .not_nil!)
            
            return io.to_slice         
        end 


        def set_time_stamp(t : Time )
            io = IO::Memory.new() 
            io.write_bytes(t.to_unix.to_i32)
            @time_date_stamp = io.to_slice 
        end 

    end

    class NTOptionalHeaders
        property magic                              : Bytes? 
        property major_linker_version               : UInt8? 
        property minor_linker_version               : UInt8? 
        property size_of_code                       : Bytes? 
        property size_of_initialized_data           : Bytes? 
        property size_of_uninitialized_data         : Bytes? 
        property address_of_entry_point             : Bytes? 
        property base_of_code                       : Bytes? 
        property base_of_data                       : Bytes? 
        property image_base                         : Bytes? 
        property section_alignment                  : Bytes? 
        property file_alignment                     : Bytes? 
        property major_operating_system_version     : Bytes? 
        property minor_operating_system_version     : Bytes? 
        property major_image_version                : Bytes? 
        property minor_image_version                : Bytes? 
        property major_subsystem_version            : Bytes? 
        property minor_subsystem_version            : Bytes? 
        property win32_version_value                : Bytes? 
        property size_of_image                      : Bytes? 
        property size_of_headers                    : Bytes? 
        property check_sum                          : Bytes? 
        property subsystem                          : Bytes? 
        property dll_characteristics                : Bytes? 
        property size_of_stack_reserve              : Bytes? 
        property size_of_stack_commit               : Bytes? 
        property size_of_heap_reserve               : Bytes? 
        property size_of_heap_commit                : Bytes? 
        property loader_flags                       : Bytes? 
        property number_of_rva_and_sizes            : Bytes? 
        property data_directory                     : DataDirectory = DataDirectory.new 



        # Property to keep track of the offset for the optionaql header
        # not part of the structure but for ease of use. 
        property optional_offset                    : Int32 = 0 




        def raw_bytes()
            io = IO::Memory.new()
            io.write( magic                              .not_nil! )
            io.write_byte( major_linker_version          .not_nil! )
            io.write_byte( minor_linker_version          .not_nil! )
            io.write( size_of_code                       .not_nil! )
            io.write( size_of_initialized_data           .not_nil! )
            io.write( size_of_uninitialized_data         .not_nil! )
            io.write( address_of_entry_point             .not_nil! )
            io.write( base_of_code                       .not_nil! )
            io.write( base_of_data                       .not_nil! ) unless base_of_data.nil?
            io.write( image_base                         .not_nil! )
            io.write( section_alignment                  .not_nil! )
            io.write( file_alignment                     .not_nil! )
            io.write( major_operating_system_version     .not_nil! )
            io.write( minor_operating_system_version     .not_nil! )
            io.write( major_image_version                .not_nil! )
            io.write( minor_image_version                .not_nil! )
            io.write( major_subsystem_version            .not_nil! )
            io.write( minor_subsystem_version            .not_nil! )
            io.write( win32_version_value                .not_nil! )
            io.write( size_of_image                      .not_nil! )
            io.write( size_of_headers                    .not_nil! )
            io.write( check_sum                          .not_nil! )
            io.write( subsystem                          .not_nil! )
            io.write( dll_characteristics                .not_nil! )
            io.write( size_of_stack_reserve              .not_nil! )
            io.write( size_of_stack_commit               .not_nil! )
            io.write( size_of_heap_reserve               .not_nil! )
            io.write( size_of_heap_commit                .not_nil! )
            io.write( loader_flags                       .not_nil! )
            io.write( number_of_rva_and_sizes            .not_nil! )
            io.write( data_directory.raw_bytes() ) 
            io.write(Bytes[0,0,0,0,0,0,0,0]) # we need to write the ending null bytes that we ignore when parsing XD 
            return io.to_slice  
    
        end 
    end 
end 