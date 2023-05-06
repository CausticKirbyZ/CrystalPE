module CrystalPE 
    class ExportedFunction 
        property ordinal              : Int32 = 0  
        property name                 : String = ""
        property function_rva         : (Bytes? | Int32) 
        property name_rva             : (Bytes? | Int32) 
        property index                : Int32 = 0 

        # not exactly sure what this is yet 
        property forwarder            : (Bytes? | Int32)
    end 
end 