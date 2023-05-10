module CrystalPE
    class ImageExportDirectory # 40 bytes long  
        property characteristics                    : Bytes?                 # DWORD
        property time_date_stamp                    : Bytes?                 # DWORD  
        property major_version                      : Bytes?                 # WORD 
        property minor_version                      : Bytes?                 # WORD  
        property name                               : Bytes?                 # DWORD
        property base                               : Bytes?                 # DWORD  
        property number_of_functions                : Bytes?                 # DWORD  
        property number_of_names                    : Bytes?                 # DWORD    
        property address_of_functions               : Bytes?                 # DWORD  
        property address_of_names                   : Bytes?                 # DWORD  
        property address_of_name_ordinals           : Bytes?                 # DWORD  

        # this property isnt part of the windows stucture but is nice to have it already resolved 
        property name_str                           : String = ""
        property offset                             : Int32 = 0 

        def set_time_stamp(t : Time )
            io = IO::Memory.new() 
            io.write_bytes(t.to_unix.to_i32)
            @time_date_stamp = io.to_slice 
        end 

        # this will set the value of the "name" pointed to in the imageExportDir 
        def set_name(str : String )
            raise "Not Implemented yet"
        end


    end 
end 