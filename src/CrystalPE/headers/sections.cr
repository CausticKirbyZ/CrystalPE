module CrystalPE 

    # class that represents a container of sections. 
    # its essentially a proxy class for a Hash(UInt64, Bytes) but with some qol built in for retrieving the sections with strings 
    class Sections 
        private property sections : Hash(UInt64, Bytes ) = Hash(UInt64, Bytes).new()


        def each
            @sections.each do |i|
                yield i
            end 
        end 

        # returns the bytes of the sections designated byt he supplied bytes. 
        # this can be used when you dont want to translate the qword to a string
        def [](i : Int64|UInt64 ) : Bytes 
            return @sections[i]
        end 

        def []=(i : Int64|UInt64, bts : Bytes  )
            # Log.trace { "Sections: Setting sections[#{i}] = #{bts[0..5]}" }
            Log.trace { "Sections: Setting sections[#{i}] = Bytes[...]" }
            @sections[i] = bts 
            Log.trace { "Sections: Sections[#{i}] set!" }
        end 
        # def []=() 
        #     yeild @sections[]=
        # end 

        # QOL function for manually referencing the section if you dont want to translate a string to a UInt64 
        # :ditto:
        def [](str : String )
            if str.size > 8 
                raise "Section name size cannot be > 8. Underlying structure is UInt64"
            end

            if str.size == 8 
                ret = str 
            else 
                ret = str += ("\0"*(8-str.size))
            end 
            
            return @sections[
                IO::ByteFormat::LittleEndian.decode(UInt64,ret.to_slice ) 
            ]
        end 


        def size() : Int32 
            return @sections.size 
        end 



        


    end 
end 