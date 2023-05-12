
# https://www.ntcore.com/files/dotnetformat.htm
#
# this class needs to be updated with more acurate information based on the above docs. the current format "works" but is not 100% acurate

module CrystalPE 
    class DotNetHeader
        property cb                                     : UInt32 = 0 
        property major_runtime_version                  : UInt16 = 0 
        property minor_runtime_version                  : UInt16 = 0 
        property meta_data_va                           : UInt32 = 0 
        property meta_data_size                         : UInt32 = 0 
        property flags                                  : UInt32 = 0 # this needs to be broken down more into what it actually means. use functions for retrieving and updating?
        property entry_point_token                      : UInt32 = 0 
        property resources_va                           : UInt32 = 0 
        property resources_size                         : UInt32 = 0 
        property strong_name_signature_va               : UInt32 = 0 
        property strong_name_signature_size             : UInt32 = 0 
        property code_manager_table_va                  : UInt32 = 0 
        property code_manager_table_size                : UInt32 = 0 
        property v_table_fixups_va                      : UInt32 = 0 
        property v_table_fixups_size                    : UInt32 = 0 
        property export_address_table_jumps_va          : UInt32 = 0 
        property export_asddress_table_jumps_size       : UInt32 = 0 
        property manage_native_header_va                : UInt32 = 0 
        property managed_native_header_size             : UInt32 = 0 


        # property parsed_offset : Int32 = -1 


        # returns the slice of the data as it would be in the pe file 
        def to_slice()
            io = IO::Memory.new 
            IO::ByteFormat::LittleEndian.encode( cb                                     ,io )
            IO::ByteFormat::LittleEndian.encode( major_runtime_version                  ,io )
            IO::ByteFormat::LittleEndian.encode( minor_runtime_version                  ,io )
            IO::ByteFormat::LittleEndian.encode( meta_data_va                           ,io )
            IO::ByteFormat::LittleEndian.encode( meta_data_size                         ,io )
            IO::ByteFormat::LittleEndian.encode( flags                                  ,io )
            IO::ByteFormat::LittleEndian.encode( entry_point_token                      ,io )
            IO::ByteFormat::LittleEndian.encode( resources_va                           ,io )
            IO::ByteFormat::LittleEndian.encode( resources_size                         ,io )
            IO::ByteFormat::LittleEndian.encode( strong_name_signature_va               ,io )
            IO::ByteFormat::LittleEndian.encode( strong_name_signature_size             ,io )
            IO::ByteFormat::LittleEndian.encode( code_manager_table_va                  ,io )
            IO::ByteFormat::LittleEndian.encode( code_manager_table_size                ,io )
            IO::ByteFormat::LittleEndian.encode( v_table_fixups_va                      ,io )
            IO::ByteFormat::LittleEndian.encode( v_table_fixups_va                      ,io )
            IO::ByteFormat::LittleEndian.encode( export_address_table_jumps_va          ,io )
            IO::ByteFormat::LittleEndian.encode( export_asddress_table_jumps_size       ,io )
            IO::ByteFormat::LittleEndian.encode( manage_native_header_va                ,io )
            IO::ByteFormat::LittleEndian.encode( managed_native_header_size             ,io )
            return io.to_slice 
        end 
    end 
end 
