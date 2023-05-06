module CrystalPE

    class ImageDataDirectory
        property virtual_address                    : Bytes? 
        property size                               : Bytes? 

        def raw_bytes()
            io = IO::Memory.new() 
            io.write(virtual_address.not_nil!)
            io.write(size.not_nil!)
            return io.to_slice 
        end 
    end

end 