module CrystalPE
    class PE_File

        property rawfile : Bytes = "0x00".to_slice

        property dos_header : DOS_Header = DOS_Header.new()
        # property sectiosn : PE_Sections


        # takes a filename on new and parses it
        def initialize(filename : String) 
            parse(filename)
        end


        # function adds a
        def parse(filename : String)
            @rawfile = File.read(filename).to_slice
            parse
        end 


        # function parses a pe file from a byte array
        def parse
            
                # do the rest of the parsing here 
                @dos_header.e_magic = rawfile[0..1]


            
        end 




    end 
end