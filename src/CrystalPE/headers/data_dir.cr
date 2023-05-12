module CrystalPE

    # PE File data directory structure. If instantiated everything is comprised of NULL Bytes
    class DataDirectory
        property export_directory                   : ImageDataDirectory = ImageDataDirectory.new()
        property import_directory                   : ImageDataDirectory = ImageDataDirectory.new()
        property resource_directory                 : ImageDataDirectory = ImageDataDirectory.new()
        property exception_directory                : ImageDataDirectory = ImageDataDirectory.new()
        property security_directory                 : ImageDataDirectory = ImageDataDirectory.new()
        property basereloc_directory                : ImageDataDirectory = ImageDataDirectory.new()
        property debug_directory                    : ImageDataDirectory = ImageDataDirectory.new()
        property architecture_directory             : ImageDataDirectory = ImageDataDirectory.new()
        property global_ptr_directory               : ImageDataDirectory = ImageDataDirectory.new()
        property tls_directory                      : ImageDataDirectory = ImageDataDirectory.new()
        property load_config_directory              : ImageDataDirectory = ImageDataDirectory.new()
        property bound_import_directory             : ImageDataDirectory = ImageDataDirectory.new()
        property iat_directory                      : ImageDataDirectory = ImageDataDirectory.new()
        property delay_import_directory             : ImageDataDirectory = ImageDataDirectory.new()
        property com_descriptor_directory           : ImageDataDirectory = ImageDataDirectory.new()


        
        def to_slice()
            io = IO::Memory.new() 
            io.write( export_directory            .to_slice() ) 
            io.write( import_directory            .to_slice() ) 
            io.write( resource_directory          .to_slice() ) 
            io.write( exception_directory         .to_slice() ) 
            io.write( security_directory          .to_slice() ) 
            io.write( basereloc_directory         .to_slice() ) 
            io.write( debug_directory             .to_slice() ) 
            io.write( architecture_directory      .to_slice() ) 
            io.write( global_ptr_directory        .to_slice() ) 
            io.write( tls_directory               .to_slice() ) 
            io.write( load_config_directory       .to_slice() ) 
            io.write( bound_import_directory      .to_slice() ) 
            io.write( iat_directory               .to_slice() ) 
            io.write( delay_import_directory      .to_slice() ) 
            io.write( com_descriptor_directory    .to_slice() ) 

            return io.to_slice 

        end 
    end 
end