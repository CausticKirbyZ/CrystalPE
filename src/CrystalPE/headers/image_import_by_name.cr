module CrystalPE 
    class ImageImportByName
        property hint : Bytes? # WORD
        # property name : Bytes? # 100 bytes long by default? 
        property name : String = ""
    end 

    class ImageImportByOrdinal 
        property name      : String = ""   # this SHOULD NEVER change.... but we want to have it for easy use 
        property ordinal   : UInt16 = 0
    end 
end 