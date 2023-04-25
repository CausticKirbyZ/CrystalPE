module CrystalPE
    def self.to_c_fmnt_hex( data : Bytes | Nil   )
        return "" if data.nil? 
        io = IO::Memory.new() 
            data.as(Bytes).each do |d| 
                io.printf("%02X", d )
            end
        return io.to_s 
    end

    def self.to_c_fmnt_hex( data : UInt8|UInt16|UInt32|UInt64|UInt128|Int8|Int16|Int32|Int64|Int128|Nil)
        return "" if data.nil? 
        io = IO::Memory.new() 
        io.printf("%02X", data )
        return io.to_s 
    end
end