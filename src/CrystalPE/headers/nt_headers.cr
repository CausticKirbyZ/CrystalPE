
module CrystalPE  

    class NTHeaders
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
        property machine                            : UInt16 = 0  # Bytes? 
        property number_of_sections                 : UInt16 = 0  # Bytes? 
        property time_date_stamp                    : UInt32 = 0  # Bytes? 
        property pointer_to_symbol_table            : UInt32 = 0  # Bytes? 
        property number_of_symbols                  : UInt32 = 0  # Bytes? 
        property size_of_optional_header            : UInt16 = 0  # Bytes? 
        property characteristics                    : UInt16 = 0  # Bytes? 

        def raw_bytes() : Bytes 
            io = IO::Memory.new            
            # io.write( machine.not_nil! )
            # io.write( number_of_sections         .not_nil!)
            # io.write( time_date_stamp            .not_nil!)
            # io.write( pointer_to_symbol_table    .not_nil!)
            # io.write( number_of_symbols          .not_nil!)
            # io.write( size_of_optional_header    .not_nil!)
            # io.write( characteristics            .not_nil!)
            IO::ByteFormat::LittleEndian.encode( machine                    , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_sections         , io ) 
            IO::ByteFormat::LittleEndian.encode( time_date_stamp            , io ) 
            IO::ByteFormat::LittleEndian.encode( pointer_to_symbol_table    , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_symbols          , io ) 
            IO::ByteFormat::LittleEndian.encode( size_of_optional_header    , io ) 
            IO::ByteFormat::LittleEndian.encode( characteristics            , io ) 
            
            return io.to_slice         
        end 


        def set_time_stamp(t : Time )
            # io = IO::Memory.new() 
            # io.write_bytes(t.to_unix.to_i32)
            # @time_date_stamp = io.to_slice 
            @time_date_stamp = t.to_unix.to_u32 
        end 

    end

    class NTOptionalHeaders
        property magic                              : UInt16            = 0 
        
        property major_linker_version               : UInt8             = 0 
        property minor_linker_version               : UInt8             = 0 
        property size_of_code                       : UInt32            = 0            # Bytes? 
        property size_of_initialized_data           : UInt32            = 0            # Bytes? 
        property size_of_uninitialized_data         : UInt32            = 0            # Bytes? 
        property address_of_entry_point             : UInt32            = 0            # Bytes? 
        
        property base_of_code                       : UInt32            = 0   # Bytes? 
        property base_of_data                       : UInt32            = 0  # Bytes? # only exists in 32 bit so set it to -1 in cases 
        property image_base                         : UInt32|UInt64     = 0   # Bytes? # is 32 bits in 32bit and 64 in 64 bit 
        
        property section_alignment                  : UInt32            = 0 # Bytes? 
        property file_alignment                     : UInt32            = 0 # Bytes? 
        property major_operating_system_version     : UInt16            = 0 # Bytes? 
        property minor_operating_system_version     : UInt16            = 0 # Bytes? 
        property major_image_version                : UInt16            = 0 # Bytes? 
        property minor_image_version                : UInt16            = 0 # Bytes? 
        property major_subsystem_version            : UInt16            = 0 # Bytes? 
        property minor_subsystem_version            : UInt16            = 0 # Bytes?
        property win32_version_value                : UInt32            = 0 # Bytes? 
        property size_of_image                      : UInt32            = 0 # Bytes? 
        property size_of_headers                    : UInt32            = 0 # Bytes? 
        property check_sum                          : UInt32            = 0 # Bytes? 
        property subsystem                          : UInt16            = 0 # Bytes? 
        property dll_characteristics                : UInt16            = 0 # Bytes? 
       
        property size_of_stack_reserve              : UInt32|UInt64            = 0 # Bytes?  # is 32 bits for x86 and 64 bits for x64 
        property size_of_stack_commit               : UInt32|UInt64            = 0 # Bytes?  # is 32 bits for x86 and 64 bits for x64 
        property size_of_heap_reserve               : UInt32|UInt64            = 0 # Bytes?  # is 32 bits for x86 and 64 bits for x64 
        property size_of_heap_commit                : UInt32|UInt64            = 0 # Bytes?  # is 32 bits for x86 and 64 bits for x64 
        
        property loader_flags                       : UInt32            = 0 # Bytes? 
        property number_of_rva_and_sizes            : UInt32            = 0 # Bytes? 


        property data_directory                     : DataDirectory = DataDirectory.new 



        # Property to keep track of the offset for the optionaql header
        # not part of the structure but for ease of use. 
        property optional_offset                    : Int32 = 0 




        def raw_bytes()
            io = IO::Memory.new()
            # io.write( magic                              .not_nil! )
            # io.write_byte( major_linker_version          .not_nil! )
            # io.write_byte( minor_linker_version          .not_nil! )
            # io.write( size_of_code                       .not_nil! )
            # io.write( size_of_initialized_data           .not_nil! )
            # io.write( size_of_uninitialized_data         .not_nil! )
            # io.write( address_of_entry_point             .not_nil! )
            # io.write( base_of_code                       .not_nil! )
            # io.write( base_of_data                       .not_nil! ) unless base_of_data.nil?
            # io.write( image_base                         .not_nil! )
            # io.write( section_alignment                  .not_nil! )
            # io.write( file_alignment                     .not_nil! )
            # io.write( major_operating_system_version     .not_nil! )
            # io.write( minor_operating_system_version     .not_nil! )
            # io.write( major_image_version                .not_nil! )
            # io.write( minor_image_version                .not_nil! )
            # io.write( major_subsystem_version            .not_nil! )
            # io.write( minor_subsystem_version            .not_nil! )
            # io.write( win32_version_value                .not_nil! )
            # io.write( size_of_image                      .not_nil! )
            # io.write( size_of_headers                    .not_nil! )
            # io.write( check_sum                          .not_nil! )
            # io.write( subsystem                          .not_nil! )
            # io.write( dll_characteristics                .not_nil! )
            # io.write( size_of_stack_reserve              .not_nil! )
            # io.write( size_of_stack_commit               .not_nil! )
            # io.write( size_of_heap_reserve               .not_nil! )
            # io.write( size_of_heap_commit                .not_nil! )
            # io.write( loader_flags                       .not_nil! )
            # io.write( number_of_rva_and_sizes            .not_nil! )
            IO::ByteFormat::LittleEndian.encode( magic                          , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode( major_linker_version           , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode( minor_linker_version           , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_code                    , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_initialized_data        , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_uninitialized_data      , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(address_of_entry_point          , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(base_of_code                    , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(base_of_data                    , io ) if image_base.class == UInt32 # this should take care of if its 32 bit#    .not_nil! ) unless base_of_data.nil?
            IO::ByteFormat::LittleEndian.encode(image_base                      , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(section_alignment               , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(file_alignment                  , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(major_operating_system_version  , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(minor_operating_system_version  , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(major_image_version             , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(minor_image_version             , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(major_subsystem_version         , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(minor_subsystem_version         , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(win32_version_value             , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_image                   , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_headers                 , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(check_sum                       , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(subsystem                       , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(dll_characteristics             , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_stack_reserve           , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_stack_commit            , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_heap_reserve            , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(size_of_heap_commit             , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(loader_flags                    , io ) #    .not_nil! )
            IO::ByteFormat::LittleEndian.encode(number_of_rva_and_sizes         , io ) #    .not_nil! )


            io.write( data_directory.to_slice() ) 
            io.write(Bytes[0,0,0,0,0,0,0,0]) # we need to write the ending null bytes that we ignore when parsing XD 
            return io.to_slice  
    
        end 
    end 
end 