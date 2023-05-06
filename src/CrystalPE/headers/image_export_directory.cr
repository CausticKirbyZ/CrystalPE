
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
end 