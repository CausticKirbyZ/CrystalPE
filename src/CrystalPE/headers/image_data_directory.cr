module CrystalPE

    class ImageDataDirectory
        property virtual_address                    : UInt32  = 0 
        property size                               : UInt32  = 0 

        def to_slice()
            io = IO::Memory.new() 
            IO::ByteFormat::LittleEndian.encode( @virtual_address, io) 
            IO::ByteFormat::LittleEndian.encode( @size, io) 
            # io.write(virtual_address.not_nil!)
            # io.write(size.not_nil!)
            return io.to_slice 
        end 
    end

end 