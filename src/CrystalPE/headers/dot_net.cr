
# https://www.ntcore.com/files/dotnetformat.htm
#
# this class needs to be updated with more acurate information based on the above docs. the current format "works" but is not 100% acurate

module CrystalPE 


    # class DotNet 
    #     header   : DotNetHeader         = DotNetHeader.new
    #     metadata : DotNetMetadataHeader = DotNetMetadataHeader.new
    # end 

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







    class DotNetMetadataHeader
        property signature                : UInt32  = 0 
        property major_version            : UInt16  = 0 
        property minor_version            : UInt16  = 0 
        property reserved1                : UInt32  = 0 
        property version_string_length    : UInt32  = 0 
        property version_string           : String  = ""  # its a string of size version_string_length rounded up to 4 
        property flags                    : UInt16  = 0 # should always be 0x00 0x00 
        property number_of_streams        : UInt16  = 0 


        def self.from_bytes(bytes : Bytes ) : DotNetMetadataHeader
            bb = bytes.to_unsafe.as(DotNetlib::MetaDataHeader_1*).value
            # puts "signature            : #{ to_c_fmnt_hex bb.signature            } | #{ to_c_fmnt_hex bytes[0..4]}"
            # puts "major_version        : #{ to_c_fmnt_hex bb.major_version        }"
            # puts "minor_version        : #{ to_c_fmnt_hex bb.minor_version        }"
            # puts "reserved1            : #{ to_c_fmnt_hex bb.reserved1            }"
            # puts "version_string_length: #{ to_c_fmnt_hex bb.version_string_length}"



            dd = DotNetMetadataHeader.new() 
            
            dd.signature                = bb.signature                
            dd.major_version            = bb.major_version            
            dd.minor_version            = bb.minor_version            
            dd.reserved1                = bb.reserved1                
            dd.version_string_length    = bb.version_string_length    

            dd.version_string           = String.new( bytes[ 16 .. 16 + bb.version_string_length ]   ) 

            b2 = bytes[16 + bb.version_string_length  ..  ].to_unsafe.as(DotNetlib::MetaDataHeader_2*).value

            # puts "version_string       : #{ b2.version_string       }"
            Log.trace { "flags                : #{ CrystalPE.to_c_fmnt_hex b2.flags                }" }
            Log.trace { "number_of_streams    : #{ CrystalPE.to_c_fmnt_hex b2.number_of_streams    }" }
            
            dd.flags                    = b2.flags                    
            dd.number_of_streams        = b2.number_of_streams        



            return dd 
        end 
    end 

    class DotNetStreamheader 
        property offset : UInt32  = 0
        property size   : UInt32  = 0
        property name   : String = "" 

        def self.from_bytes (bytes : Bytes ) : DotNetStreamheader
            ret = DotNetStreamheader.new
            ret.offset = IO::ByteFormat::LittleEndian.decode(UInt32, bytes[0..3]) 
            ret.size   = IO::ByteFormat::LittleEndian.decode(UInt32, bytes[4..7]) 
            ret.name = String.new(bytes[8.. 8 + ret.size])
            return ret 
        end 

    end 






    lib DotNetlib
        struct MetaDataHeader_1
            signature                : UInt32
            major_version            : UInt16
            minor_version            : UInt16
            reserved1                : UInt32
            version_string_length    : UInt32
            # version_string           : UInt8 *  # its a string of size version_string_length rounded up to 4 
            # flags                    : UInt16
            # number_of_streams        : UInt32
        end 
        struct MetaDataHeader_2
            flags                    : UInt16
            number_of_streams        : UInt16
        end 
    end 



end 
