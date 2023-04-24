module CrystalPE
    class PE_File

        property rawfile : Bytes = "0x00".to_slice # this is a default of nothing 

        property dos_header   : DOS_Header    = DOS_Header.new()
        property dos_stub     : DOS_Stub      = DOS_Stub.new()
        property rich_header  : RichHeader    = RichHeader.new()

        property nt_headers    : NT_Headers    = NT_Headers.new()
        # property sec_table    : SectionTable  = SectionTable.new()
        

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
                io = IO::Memory.new @rawfile 


                # This section parses the DOS Header into its structure. its well defined and is 64 bytes long
                @dos_header.e_magic    = rawfile[0..1]
                @dos_header.e_cblp     = rawfile[2..3]
                @dos_header.e_cp       = rawfile[4..5]
                @dos_header.e_crlc     = rawfile[6..7]
                @dos_header.e_cparhdr  = rawfile[8..9]
                @dos_header.e_minalloc = rawfile[10..11]
                @dos_header.e_maxalloc = rawfile[12..13]
                @dos_header.e_ss       = rawfile[14..15]
                @dos_header.e_sp       = rawfile[16..17]
                @dos_header.e_csum     = rawfile[18..19]
                @dos_header.e_ip       = rawfile[20..21]
                @dos_header.e_cs       = rawfile[22..23]
                @dos_header.e_lfarlc   = rawfile[24..25]
                @dos_header.e_ovno     = rawfile[26..27]
                @dos_header.e_res      = rawfile[28..35]
                @dos_header.e_oemid    = rawfile[36..37]
                @dos_header.e_oeminfo  = rawfile[38..39]
                @dos_header.e_res2     = rawfile[40..59]
                @dos_header.e_lfanew   = rawfile[60..64]
                
                # set temp so we dont have to use the full var name XD
                e_lfanew = IO::ByteFormat::LittleEndian.decode(Int32, rawfile[60..64] )

                # now parse the nt file headers
                @nt_headers.signature = rawfile[e_lfanew..(e_lfanew+3)] # should be PE00
                # @nt_headers.file_headers = NTFileHeaders.new()
                # @nt_headers.optional_headers = NTOptionalHeaders.new()

                @nt_headers.file_headers.machine                                    = rawfile[(e_lfanew+4)..(e_lfanew+5)]
                @nt_headers.file_headers.number_of_sections                         = rawfile[(e_lfanew+6)..(e_lfanew+7)]
                @nt_headers.file_headers.time_date_stamp                            = rawfile[(e_lfanew+8)..(e_lfanew+11)]
                @nt_headers.file_headers.pointer_to_symbol_table                    = rawfile[(e_lfanew+12)..(e_lfanew+15)]
                @nt_headers.file_headers.number_of_symbols                          = rawfile[(e_lfanew+16)..(e_lfanew+19)]
                @nt_headers.file_headers.size_of_optional_header                    = rawfile[(e_lfanew+20)..(e_lfanew+21)]
                @nt_headers.file_headers.characteristics                            = rawfile[(e_lfanew+22)..(e_lfanew+23)]

                fh_offset = e_lfanew+24

                # now parse the optional headers 
                @nt_headers.optional_headers.magic                                 = rawfile[fh_offset..(fh_offset + 1)]

                # now handle if the program is 32 bit
                # magic bytes should be 0B02 for x64 
                if @nt_headers.optional_headers.magic == Bytes[0x0B,0x01]  # this is x86 binary then 
                    @nt_headers.optional_headers.major_linker_version               = rawfile[(fh_offset + 2)]
                    @nt_headers.optional_headers.minor_linker_version               = rawfile[(fh_offset + 3)]
                    @nt_headers.optional_headers.size_of_code                       = rawfile[(fh_offset + 4)..(fh_offset + 7)]
                    @nt_headers.optional_headers.size_of_initialized_data           = rawfile[(fh_offset + 8)..(fh_offset + 11)]
                    @nt_headers.optional_headers.size_of_uninitialized_data         = rawfile[(fh_offset + 12)..(fh_offset + 15)]
                    @nt_headers.optional_headers.address_of_entry_point             = rawfile[(fh_offset + 16)..(fh_offset + 19)]
                    @nt_headers.optional_headers.base_of_code                       = rawfile[(fh_offset + 20)..(fh_offset + 23)]
                    @nt_headers.optional_headers.base_of_data                       = rawfile[(fh_offset + 24)..(fh_offset + 27)]
                    @nt_headers.optional_headers.image_base                         = rawfile[(fh_offset + 28)..(fh_offset + 35)]
                    @nt_headers.optional_headers.section_alignment                  = rawfile[(fh_offset + 36)..(fh_offset + 39)]
                    @nt_headers.optional_headers.file_alignment                     = rawfile[(fh_offset + 40)..(fh_offset + 43)]
                    @nt_headers.optional_headers.major_operating_system_version     = rawfile[(fh_offset + 44)..(fh_offset + 45)]
                    @nt_headers.optional_headers.minor_operating_system_version     = rawfile[(fh_offset + 46)..(fh_offset + 47)]
                    @nt_headers.optional_headers.major_image_version                = rawfile[(fh_offset + 48)..(fh_offset + 49)]
                    @nt_headers.optional_headers.minor_image_version                = rawfile[(fh_offset + 50)..(fh_offset + 51)]
                    @nt_headers.optional_headers.major_subsystem_version            = rawfile[(fh_offset + 52)..(fh_offset + 53)]
                    @nt_headers.optional_headers.minor_subsystem_version            = rawfile[(fh_offset + 54)..(fh_offset + 55)]
                    @nt_headers.optional_headers.win32_version_value                = rawfile[(fh_offset + 56)..(fh_offset + 59)]
                    @nt_headers.optional_headers.size_of_image                      = rawfile[(fh_offset + 60)..(fh_offset + 63)]
                    @nt_headers.optional_headers.size_of_headers                    = rawfile[(fh_offset + 64)..(fh_offset + 67)]
                    @nt_headers.optional_headers.check_sum                          = rawfile[(fh_offset + 68)..(fh_offset + 71)]
                    @nt_headers.optional_headers.subsystem                          = rawfile[(fh_offset + 72)..(fh_offset + 73)]
                    @nt_headers.optional_headers.dll_characteristics                = rawfile[(fh_offset + 74)..(fh_offset + 75)]
                    @nt_headers.optional_headers.size_of_stack_reserve              = rawfile[(fh_offset + 76)..(fh_offset + 83)]
                    @nt_headers.optional_headers.size_of_stack_commit               = rawfile[(fh_offset + 84)..(fh_offset + 91)]
                    @nt_headers.optional_headers.size_of_heap_reserve               = rawfile[(fh_offset + 92)..(fh_offset + 99)]
                    @nt_headers.optional_headers.size_of_heap_commit                = rawfile[(fh_offset + 100)..(fh_offset + 107)]
                    @nt_headers.optional_headers.loader_flags                       = rawfile[(fh_offset + 108)..(fh_offset + 111)]
                    @nt_headers.optional_headers.number_of_rva_and_sizes            = rawfile[(fh_offset + 112)..(fh_offset + 115)]

                elsif  @nt_headers.optional_headers.magic == Bytes[0x0B,0x02] # this is for x64 bit binaries 
                    @nt_headers.optional_headers.major_linker_version               = rawfile[(fh_offset + 2)]
                    @nt_headers.optional_headers.minor_linker_version               = rawfile[(fh_offset + 3)]
                    @nt_headers.optional_headers.size_of_code                       = rawfile[(fh_offset + 4)..(fh_offset + 7)]
                    @nt_headers.optional_headers.size_of_initialized_data           = rawfile[(fh_offset + 8)..(fh_offset + 11)]
                    @nt_headers.optional_headers.size_of_uninitialized_data         = rawfile[(fh_offset + 12)..(fh_offset + 15)]
                    @nt_headers.optional_headers.address_of_entry_point             = rawfile[(fh_offset + 16)..(fh_offset + 19)]
                    @nt_headers.optional_headers.base_of_code                       = rawfile[(fh_offset + 20)..(fh_offset + 23)]
                    @nt_headers.optional_headers.image_base                         = rawfile[(fh_offset + 24)..(fh_offset + 31)]
                    @nt_headers.optional_headers.section_alignment                  = rawfile[(fh_offset + 32)..(fh_offset + 35)]
                    @nt_headers.optional_headers.file_alignment                     = rawfile[(fh_offset + 36)..(fh_offset + 39)]
                    @nt_headers.optional_headers.major_operating_system_version     = rawfile[(fh_offset + 40)..(fh_offset + 41)]
                    @nt_headers.optional_headers.minor_operating_system_version     = rawfile[(fh_offset + 42)..(fh_offset + 43)]
                    @nt_headers.optional_headers.major_image_version                = rawfile[(fh_offset + 44)..(fh_offset + 45)]
                    @nt_headers.optional_headers.minor_image_version                = rawfile[(fh_offset + 46)..(fh_offset + 47)]
                    @nt_headers.optional_headers.major_subsystem_version            = rawfile[(fh_offset + 48)..(fh_offset + 49)]
                    @nt_headers.optional_headers.minor_subsystem_version            = rawfile[(fh_offset + 50)..(fh_offset + 51)]
                    @nt_headers.optional_headers.win32_version_value                = rawfile[(fh_offset + 52)..(fh_offset + 55)]
                    @nt_headers.optional_headers.size_of_image                      = rawfile[(fh_offset + 56)..(fh_offset + 59)]
                    @nt_headers.optional_headers.size_of_headers                    = rawfile[(fh_offset + 60)..(fh_offset + 63)]
                    @nt_headers.optional_headers.check_sum                          = rawfile[(fh_offset + 64)..(fh_offset + 67)]
                    @nt_headers.optional_headers.subsystem                          = rawfile[(fh_offset + 68)..(fh_offset + 69)]
                    @nt_headers.optional_headers.dll_characteristics                = rawfile[(fh_offset + 70)..(fh_offset + 71)]

                    @nt_headers.optional_headers.size_of_stack_reserve              = rawfile[(fh_offset + 72)..(fh_offset + 79)]
                    @nt_headers.optional_headers.size_of_stack_commit               = rawfile[(fh_offset + 80)..(fh_offset + 87)]
                    @nt_headers.optional_headers.size_of_heap_reserve               = rawfile[(fh_offset + 88)..(fh_offset + 95)]
                    @nt_headers.optional_headers.size_of_heap_commit                = rawfile[(fh_offset + 96)..(fh_offset + 103)]
                    @nt_headers.optional_headers.loader_flags                       = rawfile[(fh_offset + 104)..(fh_offset + 107)]
                    @nt_headers.optional_headers.number_of_rva_and_sizes            = rawfile[(fh_offset + 108)..(fh_offset + 111)]
                    dd_offset = fh_offset + 112
                    # now the data directory 

                    # its 16 sets of 2x4 byte chunks so 64 bytes
                    16.times do |i|
                        puts (i*8) + dd_offset 
                        d = ImageDataDirectory.new()
                        d.virtual_address  = rawfile[(dd_offset + (i*8))..(dd_offset + (i*8 + 3))]
                        d.size             = rawfile[(dd_offset + ((i*8) + 4))..(dd_offset + ((i*8) + 7))]

                        case i 
                        when 0 
                            @nt_headers.optional_headers.data_directory.export_directory = d
                        when 1 
                            @nt_headers.optional_headers.data_directory.import_directory = d
                        when 2 
                            @nt_headers.optional_headers.data_directory.resource_directory  = d
                        when 3 
                            @nt_headers.optional_headers.data_directory.exception_directory  = d
                        when 4 
                            @nt_headers.optional_headers.data_directory.security_directory   = d
                        when 5 
                            @nt_headers.optional_headers.data_directory.basereloc_directory = d
                        when 6 
                            @nt_headers.optional_headers.data_directory.debug_directory = d
                        when 7 
                            @nt_headers.optional_headers.data_directory.architecture_directory = d
                        when 8 
                            @nt_headers.optional_headers.data_directory.global_ptr_directory = d
                        when 9 
                            @nt_headers.optional_headers.data_directory.tls_directory = d
                        when 10 
                            @nt_headers.optional_headers.data_directory.load_config_directory = d
                        when 11 
                            @nt_headers.optional_headers.data_directory.bound_import_directory = d
                        when 12 
                            @nt_headers.optional_headers.data_directory.iat_directory = d
                        when 13 
                            @nt_headers.optional_headers.data_directory.delay_import_directory = d
                        when 14 
                            @nt_headers.optional_headers.data_directory.com_descriptor_directory = d
                        when 15 
                            # this one shouldnt exist XD but maybe some day???
                        end 

                    end 





                else 
                    raise "Error Optional Bytes indicate a Non X86 or X64 binary. we cant parse this!!!"
                end 

                




            
        end 


        def is64bit?
            return @nt_headers.optional_headers.magic == Bytes[0x0B,0x02]
        end

        def is32bit?
            return @nt_headers.optional_headers.magic == Bytes[0x0B,0x01]
        end

        def shannon_entropy : Float64 
            data = rawfile
            frequency = Hash(UInt8, Int32).new(0)
            data.each { |byte| frequency[byte] += 1 }
            data_size = data.size.to_f
            entropy = 0.0
            frequency.each do |byte, count|
                probability = count / data_size
                entropy += probability * Math.log(probability, 2)
            end
            -entropy
        end

    end 
end