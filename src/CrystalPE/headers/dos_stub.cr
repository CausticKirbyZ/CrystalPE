module CrystalPE
    
    class DOS_Stub 
        # property stub 
        property bytes : Bytes? 


        def raw_bytes() : Bytes 
            if @bytes.nil? 
                return Bytes[] # return empty set of bytes if its nil 
            end 
            return @bytes.not_nil!
        end 

    end

end