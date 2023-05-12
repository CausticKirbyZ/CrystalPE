module CrystalPE 
    class Overlay 
        # this is the raw bytes from the parsed overlay. 
        property bytes : Bytes = Bytes[]

        # set to -1 by default 
        property offset : UInt32|Int32 = -1 

    end 
end 