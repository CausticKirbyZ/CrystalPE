
module CrystalPE
    class RichHeader
        # these are the actual fields present in the rich header structure. 
        # according to this https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/
        # its the dans header then 3 paddings of 8 bytes each then an array of RichHeaderEntry followed by the "Rich" header and the xor Key
        # looking at several binaries, it looks like there is an 8 byte null chunk at the end too but undocumented
        
        # rich structure 
        # --------------------------
        # dans ^ checksum, checksum, checksum, checksum 
        # rich_entry ^ checksum...etc  
        # rich_id("Rich"), xorkey, 0,0,0....etc 
        # --------------------------
        
        property dans_id                : Bytes = Bytes[0x44, 0x61, 0x6e, 0x53 ] # "DanS" as a dword 
        
        # all 3 checksums should ideally be the same but when parsing they technically could be different
        property checksum_pad1          : Bytes = Bytes[0x0, 0x0, 0x0, 0x0]
        property checksum_pad2          : Bytes = Bytes[0x0, 0x0, 0x0, 0x0]
        property checksum_pad3          : Bytes = Bytes[0x0, 0x0, 0x0, 0x0]
        
        # this is the array of actual values for the versions and count of each entry 
        property comp_ids               : Array(RichHeaderEntry) = [] of RichHeaderEntry

        # "Rich" identifier that signifies the end/marker of the rich header 
        property rich_id                : Bytes = Bytes[0x52, 0x69, 0x63, 0x68] # "Rich" as a dword byte array 
        
        # the non null value that is the xor key that unencrypts the whole rich header values
        property xor_key                : Bytes = Bytes[0x0,0x0,0x0,0x0]

        property padding                : Bytes = Bytes[0x0,0x0,0x0,0x0, 0x0,0x0,0x0,0x0] # this needs to be here but its size is not set in stone 


        # property to store the original raw bytes
        # property bytes                  : Bytes? 


        # takes in the raw values 
        def self.xor_crypt(value : Bytes , key : Bytes ) : Bytes
            return value.map_with_index { |vv, i| vv = vv ^ key[i % key.size ] }
        end 
        
        private def xor_crypt(value : Bytes ) : Bytes
            return value.map_with_index { |vv, i| vv = vv ^ @xor_key[i % @xor_key.size ] }
        end 

        # returns the last index of b inside of a
        private def rev_ind(a : Bytes, b : Bytes ) : Int32 
            ind = a.size - b.size - 1 # last index that b would fit in 
            while ind >= 0 
              # puts "a[#{ind}]: #{a[ind..ind + b.size - 1 ] } | b: #{b}" 
              if a[ind..ind + b.size - 1 ] == b 
                break
              end 
              ind = ind - 1 
            end 
            return ind 
        end

        private def self.rev_ind(a : Bytes, b : Bytes ) : Int32 
            ind = a.size - b.size - 1 # last index that b would fit in 
            while ind >= 0 
            #   puts "a[#{ind}]: #{a[ind..ind + b.size - 1 ] } | b: #{b}" 
              if a[ind..ind + b.size - 1 ] == b 
                break
              end 
              ind = ind - 1 
            end 
            return ind 
        end

        


        # # this function is designed to be passed in a slice consisting of the Dos header, stub, and cleartext values of the rich header
        # def calc_checksum(dos_header : Bytes, dos_stub : Bytes ) : Bytes 

        # end 


        # returns a byte slice of the rich header. this does not encrypt the values prior to the rich header 
        # but instead represents them in an unencrypted state 
        def to_slice() : Bytes 
            io = IO::Memory.new() 
            
            io.write dans_id
            io.write checksum_pad1
            io.write checksum_pad2
            io.write checksum_pad3

            comp_ids.each do |cmp_id| 
                io.write cmp_id.to_slice
            end
            
            io.write rich_id
            io.write xor_key
            io.write padding # this should get dynamically updated here before being returned so it is the correct size 


            return io.to_slice
        end



        # returns the contents of the rich header in a le formatted byte array. all values are correctly formatted and encrypted as represented in a pefile. 
        def to_pe_slice() : Bytes 
            io = IO::Memory.new() 
            
            io.write xor_crypt(dans_id)
            io.write xor_crypt(checksum_pad1)
            io.write xor_crypt(checksum_pad2)
            io.write xor_crypt(checksum_pad3)

            comp_ids.each do |cmp_id| 
                io.write xor_crypt(cmp_id.to_slice)
            end
            
            io.write rich_id
            io.write xor_key
            io.write padding # this should get dynamically updated here before being returned so it is the correct size 


            return io.to_slice
        end

        def size() : Int32 
            return to_slice().size
        end 



        # this function parses the entire dos stub and returns a rich header that was parsed from it. 
        # this does not check if the parsed checksum is valid or not!
        def self.from_dos_stub(dos_stub : Bytes) : RichHeader 
            # cretae a new rich header for the return value
            ret = RichHeader.new()         
            
            
            # identify the last index of the "Rich" value 
            # rich_index = String.new(dos_stub).rindex("Rich")
            # rindex is broken with strings and how it parses resulting in inconsistent/inacurate results at times. 
            # use internal function for this 
            rich_index = rev_ind(dos_stub, "Rich".to_slice)
            
            # rich_index = dos_stub.rindex(Bytes[0x52, 0x69, 0x63, 0x68])
            Log.trace {"rich_index: #{rich_index}"}
            if rich_index 
                # puts "Index of last Rich value: #{ rich_index }"

                ret.rich_id = dos_stub[rich_index..rich_index + 3 ]
                ret.xor_key = dos_stub[rich_index+4..rich_index + 7 ]
                ret.padding = dos_stub[rich_index + 8 .. ] # the padding is the rest of the dos stub till the end of the pe headers 

                # now walk backward through the dos stub from the rich header until you find the unencrypted DanS block 
                dans_index = rich_index - 4 #start from the 4 byte block before the rich stub 
                while true 
                    if dans_index < 1  # cant have any out of bounds errors XD 
                        break 
                    end 
                    stub = xor_crypt( dos_stub[dans_index..dans_index + 3 ], ret.xor_key )
                    Log.trace { "Rich Stub:  #{CrystalPE.to_c_fmnt_hex dos_stub[dans_index..dans_index + 3 ] } -xor(#{CrystalPE.to_c_fmnt_hex ret.xor_key})-> #{CrystalPE.to_c_fmnt_hex stub } = String->#{ String.new(stub ) }" }
                    if String.new( stub ) == "DanS"
                        Log.debug {"Found DanS"}
                        ret.dans_id = stub 
                        break # break so we dont decrement the index after we found it 
                    end 
                    dans_index = dans_index - 4 
                end 

                # now we can start at dans + 4 for the first checksum pad value 
                fpad_check_index = dans_index + 4 
                ret.checksum_pad1 = dos_stub[ fpad_check_index .. fpad_check_index + 3 ] 
                ret.checksum_pad2 = dos_stub[ fpad_check_index + 4 .. fpad_check_index + 7 ] 
                ret.checksum_pad3 = dos_stub[ fpad_check_index + 8 .. fpad_check_index + 11 ] 


                # now we have to parse the comp_id values 
                comp_id_1_index = fpad_check_index + 12 
                comp_id_block = dos_stub[comp_id_1_index .. rich_index - 1 ] # the comp_id's are the block between the last checksum pad and the rich header 
                # puts "comp_id_block_size: #{comp_id_block.size}"
                (comp_id_block.size / 8 ).to_i.times do |i| # loop through the divided chunks (they are 8 bytes large or 64 bits ), unencrypt and add to the rich header entry list 
                    # re = RichHeaderEntry.new()
                    ind = i*8
                    re = RichHeaderEntry.from_bytes( xor_crypt( comp_id_block[ind .. ind+7], ret.xor_key )  ) 
                    ret.comp_ids << re 
                end 
            end 

            return ret
        end 

        # returns a richg header object parsed from a section of bytes. 
        # if supplying your own NEED to recalculate the xor key to be correct as 
        # it will have likely changed from the original file. 
        def self.from_bytes(rich_stub : Bytes ) : RichHeader 
            # cretae a new rich header for the return value
            ret = RichHeader.new() 

            # identify the last index of the "Rich" value 
            # rich_index = String.new(rich_stub).rindex("Rich")

            # rindex is broken with strings and how it parses resulting in inconsistent/inacurate results at times. 
            # use internal function for this 
            rich_index = rev_ind(rich_stub, "Rich".to_slice)

            if rich_index 
                # puts "Index of last Rich value: #{ rich_index }"
                ret.rich_id = rich_stub[rich_index..rich_index + 3 ]
                ret.xor_key = rich_stub[rich_index+4..rich_index + 7 ]
                ret.padding = rich_stub[rich_index + 8 .. ] # the padding is the rest of the dos stub till the end of the pe headers 

                # now walk backward through the dos stub from the rich header until you find the unencrypted DanS block 
                dans_index = rich_index - 4 #start from the 4 byte block before the rich stub 
                while true 
                    if dans_index < 1  # cant have any out of bounds errors XD 
                        break 
                    end 
                    stub = xor_crypt( rich_stub[dans_index..dans_index + 3 ], ret.xor_key )
                    if String.new( stub ) == "DanS"
                        ret.dans_id = stub 
                        break # break so we dont decrement the index after we found it 
                    end 
                    dans_index = dans_index - 4 
                end 

                # now we can start at dans + 4 for the first checksum pad value 
                fpad_check_index = dans_index + 4 
                ret.checksum_pad1 = rich_stub[ fpad_check_index .. fpad_check_index + 3 ] 
                ret.checksum_pad2 = rich_stub[ fpad_check_index + 4 .. fpad_check_index + 7 ] 
                ret.checksum_pad3 = rich_stub[ fpad_check_index + 8 .. fpad_check_index + 11 ] 


                # now we have to parse the comp_id values 
                comp_id_1_index = fpad_check_index + 12 
                comp_id_block = rich_stub[comp_id_1_index .. rich_index - 1 ] # the comp_id's are the block between the last checksum pad and the rich header 
                # puts "comp_id_block_size: #{comp_id_block.size}"
                (comp_id_block.size / 8 ).to_i.times do |i| # loop through the divided chunks (they are 8 bytes large or 64 bits ), unencrypt and add to the rich header entry list 
                    # re = RichHeaderEntry.new()
                    ind = i*8
                    re = RichHeaderEntry.from_bytes( xor_crypt( comp_id_block[ind .. ind+7], ret.xor_key )  ) 
                    ret.comp_ids << re 
                end 
            end 
            return ret


        end 
        
        # parss a a set of `Bytes` and interprets it as a rich header. This accepts a Bytes object that should represent the entire rich header bytes. 
        def self.parse(bytes : Bytes ) : RichHeader
            ret = RichHeader.new()
            puts "Parsing Rich header"
            return ret 
        end 
    end







    class RichHeaderEntry
        property build_id  : UInt16 = 0 # 16 bit 
        property prod_id   : UInt16 = 0 # 16 bit 
        property count     : UInt32 = 0 # 32 bit 


        private property prod_id_lookup_table : Hash( Int32, String) = {
            0x0000 => "Unknown",
            0x0001 => "Import0",
            0x0002 => "Linker510",
            0x0003 => "Cvtomf510",
            0x0004 => "Linker600",
            0x0005 => "Cvtomf600",
            0x0006 => "Cvtres500",
            0x0007 => "Utc11_Basic",
            0x0008 => "Utc11_C",
            0x0009 => "Utc12_Basic",
            0x000a => "Utc12_C",
            0x000b => "Utc12_CPP",
            0x000c => "AliasObj60",
            0x000d => "VisualBasic60",
            0x000e => "Masm613",
            0x000f => "Masm710",
            0x0010 => "Linker511",
            0x0011 => "Cvtomf511",
            0x0012 => "Masm614",
            0x0013 => "Linker512",
            0x0014 => "Cvtomf512",
            0x0015 => "Utc12_C_Std",
            0x0016 => "Utc12_CPP_Std",
            0x0017 => "Utc12_C_Book",
            0x0018 => "Utc12_CPP_Book",
            0x0019 => "Implib700",
            0x001a => "Cvtomf700",
            0x001b => "Utc13_Basic",
            0x001c => "Utc13_C",
            0x001d => "Utc13_CPP",
            0x001e => "Linker610",
            0x001f => "Cvtomf610",
            0x0020 => "Linker601",
            0x0021 => "Cvtomf601",
            0x0022 => "Utc12_1_Basic",
            0x0023 => "Utc12_1_C",
            0x0024 => "Utc12_1_CPP",
            0x0025 => "Linker620",
            0x0026 => "Cvtomf620",
            0x0027 => "AliasObj70",
            0x0028 => "Linker621",
            0x0029 => "Cvtomf621",
            0x002a => "Masm615",
            0x002b => "Utc13_LTCG_C",
            0x002c => "Utc13_LTCG_CPP",
            0x002d => "Masm620",
            0x002e => "ILAsm100",
            0x002f => "Utc12_2_Basic",
            0x0030 => "Utc12_2_C",
            0x0031 => "Utc12_2_CPP",
            0x0032 => "Utc12_2_C_Std",
            0x0033 => "Utc12_2_CPP_Std",
            0x0034 => "Utc12_2_C_Book",
            0x0035 => "Utc12_2_CPP_Book",
            0x0036 => "Implib622",
            0x0037 => "Cvtomf622",
            0x0038 => "Cvtres501",
            0x0039 => "Utc13_C_Std",
            0x003a => "Utc13_CPP_Std",
            0x003b => "Cvtpgd1300",
            0x003c => "Linker622",
            0x003d => "Linker700",
            0x003e => "Export622",
            0x003f => "Export700",
            0x0040 => "Masm700",
            0x0041 => "Utc13_POGO_I_C",
            0x0042 => "Utc13_POGO_I_CPP",
            0x0043 => "Utc13_POGO_O_C",
            0x0044 => "Utc13_POGO_O_CPP",
            0x0045 => "Cvtres700",
            0x0046 => "Cvtres710p",
            0x0047 => "Linker710p",
            0x0048 => "Cvtomf710p",
            0x0049 => "Export710p",
            0x004a => "Implib710p",
            0x004b => "Masm710p",
            0x004c => "Utc1310p_C",
            0x004d => "Utc1310p_CPP",
            0x004e => "Utc1310p_C_Std",
            0x004f => "Utc1310p_CPP_Std",
            0x0050 => "Utc1310p_LTCG_C",
            0x0051 => "Utc1310p_LTCG_CPP",
            0x0052 => "Utc1310p_POGO_I_C",
            0x0053 => "Utc1310p_POGO_I_CPP",
            0x0054 => "Utc1310p_POGO_O_C",
            0x0055 => "Utc1310p_POGO_O_CPP",
            0x0056 => "Linker624",
            0x0057 => "Cvtomf624",
            0x0058 => "Export624",
            0x0059 => "Implib624",
            0x005a => "Linker710",
            0x005b => "Cvtomf710",
            0x005c => "Export710",
            0x005d => "Implib710",
            0x005e => "Cvtres710",
            0x005f => "Utc1310_C",
            0x0060 => "Utc1310_CPP",
            0x0061 => "Utc1310_C_Std",
            0x0062 => "Utc1310_CPP_Std",
            0x0063 => "Utc1310_LTCG_C",
            0x0064 => "Utc1310_LTCG_CPP",
            0x0065 => "Utc1310_POGO_I_C",
            0x0066 => "Utc1310_POGO_I_CPP",
            0x0067 => "Utc1310_POGO_O_C",
            0x0068 => "Utc1310_POGO_O_CPP",
            0x0069 => "AliasObj710",
            0x006a => "AliasObj710p",
            0x006b => "Cvtpgd1310",
            0x006c => "Cvtpgd1310p",
            0x006d => "Utc1400_C",
            0x006e => "Utc1400_CPP",
            0x006f => "Utc1400_C_Std",
            0x0070 => "Utc1400_CPP_Std",
            0x0071 => "Utc1400_LTCG_C",
            0x0072 => "Utc1400_LTCG_CPP",
            0x0073 => "Utc1400_POGO_I_C",
            0x0074 => "Utc1400_POGO_I_CPP",
            0x0075 => "Utc1400_POGO_O_C",
            0x0076 => "Utc1400_POGO_O_CPP",
            0x0077 => "Cvtpgd1400",
            0x0078 => "Linker800",
            0x0079 => "Cvtomf800",
            0x007a => "Export800",
            0x007b => "Implib800",
            0x007c => "Cvtres800",
            0x007d => "Masm800",
            0x007e => "AliasObj800",
            0x007f => "PhoenixPrerelease",
            0x0080 => "Utc1400_CVTCIL_C",
            0x0081 => "Utc1400_CVTCIL_CPP",
            0x0082 => "Utc1400_LTCG_MSIL",
            0x0083 => "Utc1500_C",
            0x0084 => "Utc1500_CPP",
            0x0085 => "Utc1500_C_Std",
            0x0086 => "Utc1500_CPP_Std",
            0x0087 => "Utc1500_CVTCIL_C",
            0x0088 => "Utc1500_CVTCIL_CPP",
            0x0089 => "Utc1500_LTCG_C",
            0x008a => "Utc1500_LTCG_CPP",
            0x008b => "Utc1500_LTCG_MSIL",
            0x008c => "Utc1500_POGO_I_C",
            0x008d => "Utc1500_POGO_I_CPP",
            0x008e => "Utc1500_POGO_O_C",
            0x008f => "Utc1500_POGO_O_CPP",
            0x0090 => "Cvtpgd1500",
            0x0091 => "Linker900",
            0x0092 => "Export900",
            0x0093 => "Implib900",
            0x0094 => "Cvtres900",
            0x0095 => "Masm900",
            0x0096 => "AliasObj900",
            0x0097 => "Resource",
            0x0098 => "AliasObj1000",
            0x0099 => "Cvtpgd1600",
            0x009a => "Cvtres1000",
            0x009b => "Export1000",
            0x009c => "Implib1000",
            0x009d => "Linker1000",
            0x009e => "Masm1000",
            0x009f => "Phx1600_C",
            0x00a0 => "Phx1600_CPP",
            0x00a1 => "Phx1600_CVTCIL_C",
            0x00a2 => "Phx1600_CVTCIL_CPP",
            0x00a3 => "Phx1600_LTCG_C",
            0x00a4 => "Phx1600_LTCG_CPP",
            0x00a5 => "Phx1600_LTCG_MSIL",
            0x00a6 => "Phx1600_POGO_I_C",
            0x00a7 => "Phx1600_POGO_I_CPP",
            0x00a8 => "Phx1600_POGO_O_C",
            0x00a9 => "Phx1600_POGO_O_CPP",
            0x00aa => "Utc1600_C",
            0x00ab => "Utc1600_CPP",
            0x00ac => "Utc1600_CVTCIL_C",
            0x00ad => "Utc1600_CVTCIL_CPP",
            0x00ae => "Utc1600_LTCG_C",
            0x00af => "Utc1600_LTCG_CPP",
            0x00b0 => "Utc1600_LTCG_MSIL",
            0x00b1 => "Utc1600_POGO_I_C",
            0x00b2 => "Utc1600_POGO_I_CPP",
            0x00b3 => "Utc1600_POGO_O_C",
            0x00b4 => "Utc1600_POGO_O_CPP",
            0x00b5 => "AliasObj1010",
            0x00b6 => "Cvtpgd1610",
            0x00b7 => "Cvtres1010",
            0x00b8 => "Export1010",
            0x00b9 => "Implib1010",
            0x00ba => "Linker1010",
            0x00bb => "Masm1010",
            0x00bc => "Utc1610_C",
            0x00bd => "Utc1610_CPP",
            0x00be => "Utc1610_CVTCIL_C",
            0x00bf => "Utc1610_CVTCIL_CPP",
            0x00c0 => "Utc1610_LTCG_C",
            0x00c1 => "Utc1610_LTCG_CPP",
            0x00c2 => "Utc1610_LTCG_MSIL",
            0x00c3 => "Utc1610_POGO_I_C",
            0x00c4 => "Utc1610_POGO_I_CPP",
            0x00c5 => "Utc1610_POGO_O_C",
            0x00c6 => "Utc1610_POGO_O_CPP",
            0x00c7 => "AliasObj1100",
            0x00c8 => "Cvtpgd1700",
            0x00c9 => "Cvtres1100",
            0x00ca => "Export1100",
            0x00cb => "Implib1100",
            0x00cc => "Linker1100",
            0x00cd => "Masm1100",
            0x00ce => "Utc1700_C",
            0x00cf => "Utc1700_CPP",
            0x00d0 => "Utc1700_CVTCIL_C",
            0x00d1 => "Utc1700_CVTCIL_CPP",
            0x00d2 => "Utc1700_LTCG_C",
            0x00d3 => "Utc1700_LTCG_CPP",
            0x00d4 => "Utc1700_LTCG_MSIL",
            0x00d5 => "Utc1700_POGO_I_C",
            0x00d6 => "Utc1700_POGO_I_CPP",
            0x00d7 => "Utc1700_POGO_O_C",
            0x00d8 => "Utc1700_POGO_O_CPP",
            0x00d9 => "AliasObj1200",
            0x00da => "Cvtpgd1800",
            0x00db => "Cvtres1200",
            0x00dc => "Export1200",
            0x00dd => "Implib1200",
            0x00de => "Linker1200",
            0x00df => "Masm1200",
            0x00e0 => "Utc1800_C",
            0x00e1 => "Utc1800_CPP",
            0x00e2 => "Utc1800_CVTCIL_C",
            0x00e3 => "Utc1800_CVTCIL_CPP",
            0x00e4 => "Utc1800_LTCG_C",
            0x00e5 => "Utc1800_LTCG_CPP",
            0x00e6 => "Utc1800_LTCG_MSIL",
            0x00e7 => "Utc1800_POGO_I_C",
            0x00e8 => "Utc1800_POGO_I_CPP",
            0x00e9 => "Utc1800_POGO_O_C",
            0x00ea => "Utc1800_POGO_O_CPP",
            0x00eb => "AliasObj1210",
            0x00ec => "Cvtpgd1810",
            0x00ed => "Cvtres1210",
            0x00ee => "Export1210",
            0x00ef => "Implib1210",
            0x00f0 => "Linker1210",
            0x00f1 => "Masm1210",
            0x00f2 => "Utc1810_C",
            0x00f3 => "Utc1810_CPP",
            0x00f4 => "Utc1810_CVTCIL_C",
            0x00f5 => "Utc1810_CVTCIL_CPP",
            0x00f6 => "Utc1810_LTCG_C",
            0x00f7 => "Utc1810_LTCG_CPP",
            0x00f8 => "Utc1810_LTCG_MSIL",
            0x00f9 => "Utc1810_POGO_I_C",
            0x00fa => "Utc1810_POGO_I_CPP",
            0x00fb => "Utc1810_POGO_O_C",
            0x00fc => "Utc1810_POGO_O_CPP",
            0x00fd => "AliasObj1400",
            0x00fe => "Cvtpgd1900",
            0x00ff => "Cvtres1400",
            0x0100 => "Export1400",
            0x0101 => "Implib1400",
            0x0102 => "Linker1400",
            0x0103 => "Masm1400",
            0x0104 => "Utc1900_C",
            0x0105 => "Utc1900_CPP",
            0x0106 => "Utc1900_CVTCIL_C",
            0x0107 => "Utc1900_CVTCIL_CPP",
            0x0108 => "Utc1900_LTCG_C",
            0x0109 => "Utc1900_LTCG_CPP",
            0x010a => "Utc1900_LTCG_MSIL",
            0x010b => "Utc1900_POGO_I_C",
            0x010c => "Utc1900_POGO_I_CPP",
            0x010d => "Utc1900_POGO_O_C",
            0x010e => "Utc1900_POGO_O_CPP",
        }


        def to_slice() : Bytes 
            io = IO::Memory.new()
            IO::ByteFormat::LittleEndian.encode(@build_id, io ) 
            IO::ByteFormat::LittleEndian.encode(@prod_id, io ) 
            IO::ByteFormat::LittleEndian.encode(@count, io ) 
            return io.to_slice 
        end 


        # parses an UNENCRYPTED le formated byte array and returns a RichHeaderEntry object 
        def self.from_bytes(bytes) : RichHeaderEntry 
            re = RichHeaderEntry.new()
            re.build_id = IO::ByteFormat::LittleEndian.decode(UInt16, bytes[0..1]) 
            re.prod_id = IO::ByteFormat::LittleEndian.decode(UInt16, bytes[2..3]) 
            re.count = IO::ByteFormat::LittleEndian.decode(UInt32, bytes[4..]) 
            return re 
        end


        # def self.build_id_string( id : Int32 ) : String 
        # end 

        def self.prod_id_string(id : Int16) : String 
            if id > 0x010e
                return @prod_id_lookup_table[0x0000] # return "Unknown" if its not in the lookup table 
            else 
                return @prod_id_lookup_table[id]
            end 
        end 

        def prod_id_string() : String 
            if @prod_id > 0x010e
                return @prod_id_lookup_table[0x0000] # return "Unknown" if its not in the lookup table 
            else 
                return @prod_id_lookup_table[@prod_id]
            end 
        end 

        def prod_id_vs_version() : String 
            # if @prod_id > 0x010e 
            #     return ""
            # elsif @prod_id 
            # elsif @prod_id >= 0x00fd && @prod_id < 0x010e+1 
            #     return "Visual Studio 2015 14.00"
            # elsif @prod_id >= 0x00eb && @prod_id < 0x00fd 
            #     return "Visual Studio 2013 12.10"
            # elsif @prod_id >= 0x00d9 && @prod_id < 0x00eb 
            #     return "Visual Studio 2013 12.00"
            # elsif @prod_id >= 0x00c7 && @prod_id < 0x00d9 
            #     return "Visual Studio 2012 11.00"
            # elsif @prod_id >= 0x00b5 && @prod_id < 0x00c7 
            #     return "Visual Studio 2010 10.10"
            # elsif @prod_id >= 0x0098 && @prod_id < 0x00b5 
            #     return "Visual Studio 2010 10.00"
            # elsif @prod_id >= 0x0083 && @prod_id < 0x0098 
            #     return "Visual Studio 2008 09.00"
            # elsif @prod_id >= 0x006d && @prod_id < 0x0083 
            #     return "Visual Studio 2005 08.00"
            # elsif @prod_id >= 0x005a && @prod_id < 0x006d 
            #     return "Visual Studio 2003 07.10"
            # elsif @prod_id == 1
            #     return "Visual Studio"
            # else 
            #     return "<unknown>"
            # end


            # based on https://github.com/hasherezade/bearparser/blob/master/parser/pe/RichHdrWrapper.cpp
            i = @prod_id 
            return "Visual Studio 2017 14.01+" if (i >= 0x0106 && i < (0x010a + 1))
            return "Visual Studio 2015 14.00"  if (i >= 0x00fd && i < (0x0106))
            return "Visual Studio 2013 12.10"  if (i >= 0x00eb && i < 0x00fd)
            return "Visual Studio 2013 12.00"  if (i >= 0x00d9 && i < 0x00eb)
            return "Visual Studio 2012 11.00"  if (i >= 0x00c7 && i < 0x00d9)
            return "Visual Studio 2010 10.10"  if (i >= 0x00b5 && i < 0x00c7)
            return "Visual Studio 2010 10.00"  if (i >= 0x0098 && i < 0x00b5)
            return "Visual Studio 2008 09.00"  if (i >= 0x0083 && i < 0x0098)
            return "Visual Studio 2005 08.00"  if (i >= 0x006d && i < 0x0083)
            return "Visual Studio 2003 07.10"  if (i >= 0x005a && i < 0x006d)
            return "Visual Studio 2002 07.00"  if (i >= 0x0019 && i < (0x0045 + 1))
            return "Visual Studio 6.0 06.00"   if (i == 0xA || i == 0xB || i == 0xD || i == 0x15 || i == 0x16 )
            return "Visual Studio 97 05.00"    if (i == 0x2 || i == 0x6 || i == 0xC || i == 0xE)
            return "Visual Studio"             if (i == 1)
            return ""
        end 

    end
end 