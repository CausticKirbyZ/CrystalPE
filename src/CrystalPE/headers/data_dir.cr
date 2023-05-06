module CrystalPE
    class DataDirectory
        property export_directory                   : ImageDataDirectory?
        property import_directory                   : ImageDataDirectory?
        property resource_directory                 : ImageDataDirectory?
        property exception_directory                : ImageDataDirectory?
        property security_directory                 : ImageDataDirectory?
        property basereloc_directory                : ImageDataDirectory?
        property debug_directory                    : ImageDataDirectory?
        property architecture_directory             : ImageDataDirectory?
        property global_ptr_directory               : ImageDataDirectory?
        property tls_directory                      : ImageDataDirectory?
        property load_config_directory              : ImageDataDirectory?
        property bound_import_directory             : ImageDataDirectory?
        property iat_directory                      : ImageDataDirectory?
        property delay_import_directory             : ImageDataDirectory?
        property com_descriptor_directory           : ImageDataDirectory?


        
        def raw_bytes()
            io = IO::Memory.new() 
            io.write( export_directory            .not_nil!.raw_bytes() ) 
            io.write( import_directory            .not_nil!.raw_bytes() ) 
            io.write( resource_directory          .not_nil!.raw_bytes() ) 
            io.write( exception_directory         .not_nil!.raw_bytes() ) 
            io.write( security_directory          .not_nil!.raw_bytes() ) 
            io.write( basereloc_directory         .not_nil!.raw_bytes() ) 
            io.write( debug_directory             .not_nil!.raw_bytes() ) 
            io.write( architecture_directory      .not_nil!.raw_bytes() ) 
            io.write( global_ptr_directory        .not_nil!.raw_bytes() ) 
            io.write( tls_directory               .not_nil!.raw_bytes() ) 
            io.write( load_config_directory       .not_nil!.raw_bytes() ) 
            io.write( bound_import_directory      .not_nil!.raw_bytes() ) 
            io.write( iat_directory               .not_nil!.raw_bytes() ) 
            io.write( delay_import_directory      .not_nil!.raw_bytes() ) 
            io.write( com_descriptor_directory    .not_nil!.raw_bytes() ) 

            return io.to_slice 

        end 
    end 
end