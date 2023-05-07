module CrystalPE
    class PE_File
        # property rawfile : Bytes = "0x00".to_slice # this is a default of nothing 
        property rawfile : Bytes = Bytes[] # this is a default of nothing 

        property dos_header   : DOS_Header    = DOS_Header.new()
        property dos_stub     : DOS_Stub      = DOS_Stub.new()
        property rich_header  : RichHeader    = RichHeader.new()

        property nt_headers    : NT_Headers    = NT_Headers.new()
        
        # this is kinda like an addressbook/info blob about each section
        property section_table  : Array(SectionHeader) = [] of SectionHeader

        # sections will be where we store the actuall bytes for each section
        property sections       : Hash(String, Bytes) = Hash(String, Bytes).new()

        # property overlay        : Bytes = Bytes[]
        property overlay          : Overlay = Overlay.new()


        # Import address table as an array of ImageImportDescriptors
        # property iat            : Array(ImageImportDescriptor) = [] of ImageImportDescriptor
        # property eat            : Array
        property iat            : Array(ImportedInfo) = [] of ImportedInfo

        property img_exp_dir    : ImageExportDirectory = ImageExportDirectory.new() 
        property exports        : Array(ExportedFunction) = [] of ExportedFunction



        # takes a filename on new and parses it
        def initialize(filename : String) 
            parse(filename)
        end

        def initialize(filebts : Bytes )
            parse(filebts)
        end 

        def initialize
        end


        # function adds a
        def parse(filename : String)
            @rawfile = File.read(filename).to_slice
            parse
        end 

        def parse(filebts : Bytes )
            @rawfile = filebts 
            parse 
        end 

        # returns the pefile as a byte array. good for writing to a file 
        def to_slice( ) : Bytes 
            io = IO::Memory.new() 
            # File.open(filename, "w") do |fi|
                io.write @dos_header.raw_bytes()
                io.write @dos_stub.raw_bytes()
                io.write @rich_header.raw_bytes() 
                io.write @nt_headers.raw_bytes()

                @section_table.each do |s| 
                    io.write s.raw_bytes()
                end 

                # now we have to ensure the file is aligned properly
                # this is done by adding padding between the section header and the first section 
                # to ensure the first section starts at the beginning of a multiple of the file alignment.
                # file alignment size can be found at the optional header value of "FileAlignment often at offset #BC"
                # this file padding is done with all null bytes but technically it could be anything. 

                # puts "Current Pos: #{io.pos}"       
                # puts "Offset Hex:  #{to_c_fmnt_hex(@nt_headers.optional_headers.file_alignment.not_nil!) }"         
                # puts "Offset Dec:  #{IO::ByteFormat::LittleEndian.decode(Int32,@nt_headers.optional_headers.file_alignment.not_nil!) }"         
                # puts "Difference:  #{IO::ByteFormat::LittleEndian.decode(Int32,@nt_headers.optional_headers.file_alignment.not_nil! ) - (io.pos % IO::ByteFormat::LittleEndian.decode(Int32,@nt_headers.optional_headers.file_alignment.not_nil! ))}"
                (IO::ByteFormat::LittleEndian.decode(Int32,@nt_headers.optional_headers.file_alignment.not_nil! ) - (io.pos % IO::ByteFormat::LittleEndian.decode(Int32,@nt_headers.optional_headers.file_alignment.not_nil! )) ).times do |i|
                    io.write Bytes[0]
                end 
                # end of aligning file 

                @sections.each do |k,v| 
                    # puts "Writing Secdion: #{k}"
                    # puts "Section Raw: #{to_c_fmnt_hex(v)}"
                    # gets 
                    io.write v
                end 

                io.write @overlay.bytes 

            # end 
            # File.write(filename , io.to_slice) 
            return io.to_slice 
        end 


        # function parses a pe file from a byte array
        def parse
                # do the rest of the parsing here 
                # io = IO::Memory.new @rawfile 
                # puts "dbg: rawfile[0..1]: |#{String.new(rawfile[0..1]) }|"
                # puts "dbg: rawfile[0..1]: #{rawfile[0..1] }"
                if rawfile.size < 96 # smallest recorded pe file i could find online was 97 bytes...
                    raise "Parsing Error! - Size"
                elsif String.new(rawfile[0..1]) != "MZ"
                    raise "Not a PE File.... 'MZ' != '#{String.new(rawfile[0..1])}'"
                end 



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
                @dos_header.e_lfanew   = rawfile[60..63]
                
                # set temp so we dont have to use the full var name XD
                # e_lfanew is the offset of the new exe header (pe header start)
                e_lfanew = IO::ByteFormat::LittleEndian.decode(Int32, rawfile[60..63] )
                
                # this is misleading and is actually the "Rich" offset but this gets updated later with the correct value. 
                # needs to be up here to be referenced later
                dans_offset = ( e_lfanew - 16)



                # puts "DBG: e_lfanew : #{to_c_fmnt_hex( e_lfanew) }"
                if e_lfanew > 64 
                    # dos stubs and rich headers technically dont need to exist. so only parse them if there is an offset over 64 bytes 
                    # parse the rich header 
                    # puts "DBG: #{ to_c_fmnt_hex rawfile[64..( e_lfanew - 1 )] }"

                    # if "Rich" is in the header value 
                    # if rawfile[64..( e_lfanew - 1 )].includes? Bytes[ 0x52, 0x69, 0x63, 0x68 ]
                    if String.new(rawfile[64..( e_lfanew - 1 )]).includes? "Rich"
                        # puts "DBG: Contains Rich Header!"
                        # start at 16 bytes before e_lfanew. there "should" be a "Rich" string then a 4 byte key then 8 bytes of null to end the rich header
                        rich_key_ending = rawfile[ ( e_lfanew - 16) .. ( e_lfanew - 1) ]
                        rich = rich_key_ending[0..3]
                        @rich_header.rich_id = rich_key_ending[0..3] # should be "Rich"
                        xor_key = rich_key_ending[4..7] # xor key is the next 4 bytes after "Rich"
                        @rich_header.xor_key = rich_key_ending[4..7] # xor key is the next 4 bytes after "Rich"
                        ending = rich_key_ending[8..] # followed by an 8 byte string of null(or should be)
                        puts "DBG: Got Keys and stuff"


                        dans = Bytes[]
                        if String.new(rich) == "Rich"
                            # puts "DBG: Getting dans_offset: #{dans_offset}"
                            # walk backward through the offset till we find "DanS"
                            while true 
                                # puts "DBG: New dans_offset: #{dans_offset}"
                                if dans_offset < 1 
                                    # puts "DBG: Breaking: #{dans_offset}"
                                    break 
                                end
                                
                                rich_unxored = String.new( RichHeader.xor_decrypt(rawfile[dans_offset..dans_offset+3], xor_key ) ) 
                                # puts "DBG: RichXorDeced: #{rich_unxored}"
                                if  rich_unxored == "DanS"
                                    dans = rawfile[dans_offset..dans_offset+3] # get our raw bytes 
                                    @rich_header.dans_id = rawfile[dans_offset..dans_offset+3] # get our raw bytes 
                                    # puts "DBG: Found DanS Stub"
                                    break
                                end 
                                dans_offset = dans_offset - 4 
                            end 
                            @rich_header.bytes = @rawfile[dans_offset..e_lfanew-1]
                        end 
                        
                        puts "Parsed Rich header"
                        # puts "DBG: Rich:   #{String.new rich}"
                        # puts "DBG: Key:    #{to_c_fmnt_hex(xor_key ) }"
                        # puts "DBG: ending: #{to_c_fmnt_hex(ending ) }"
                        # puts "RichRaw: #{ to_c_fmnt_hex(@rich_header.bytes ) }"
                        
                    end 

                    # end of rich header parse 



                    # now we can parse the dos stub here 
                    # we parse it after the rich header as we need to know the length of the rich header if there is one 
                    # so we can 
                    # dos header is designated as the space between the end of the dos header and the start of the PE headers 
                    if !@rich_header.bytes.nil?
                        # dos stub is actually only untill the beginning of the rich header
                        @dos_stub.bytes = rawfile[64..( dans_offset - 1 )] 
                    else 
                        # this is for those that dont have a rich header
                        # this will also trigger if the "Rich" String is not present. this may be hideable by changing the "Rich" string to something else but the encoding would still be valid 
                        @dos_stub.bytes = rawfile[64..( e_lfanew - 1 )] 
                    end 
                end 
                # end of parsing dos stub 







                # now parse the nt file headers
                @nt_headers.signature = rawfile[e_lfanew..(e_lfanew+3)] # should be PE00
                # @nt_headers.file_headers = NTFileHeaders.new()
                # @nt_headers.optional_headers = NTOptionalHeaders.new()
                
                # this will be:
                #   8664 for amd64 (x64 binary)
                #   4C01 for Intel386 (x86 binary )
                #   64AA for arm64 windows (windows 64 bit arm)
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
                @nt_headers.optional_headers.optional_offset = fh_offset 


                # now handle if the program is 32 bit
                # magic bytes should be 0B02 for x64 
                if @nt_headers.optional_headers.magic == Bytes[0x0B,0x01]  # this is x86 binary then 
                    @nt_headers.optional_headers.major_linker_version               = rawfile[(fh_offset + 2)]
                    @nt_headers.optional_headers.minor_linker_version               = rawfile[(fh_offset + 3)]
                    @nt_headers.optional_headers.size_of_code                       = rawfile[(fh_offset + 4  )..(fh_offset + 7  )]
                    @nt_headers.optional_headers.size_of_initialized_data           = rawfile[(fh_offset + 8  )..(fh_offset + 11 )]
                    @nt_headers.optional_headers.size_of_uninitialized_data         = rawfile[(fh_offset + 12 )..(fh_offset + 15 )]
                    @nt_headers.optional_headers.address_of_entry_point             = rawfile[(fh_offset + 16 )..(fh_offset + 19 )]
                    @nt_headers.optional_headers.base_of_code                       = rawfile[(fh_offset + 20 )..(fh_offset + 23 )]
                    @nt_headers.optional_headers.base_of_data                       = rawfile[(fh_offset + 24 )..(fh_offset + 27 )]
                    
                    @nt_headers.optional_headers.image_base                         = rawfile[(fh_offset + 28 )..(fh_offset + 31 )]
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

                    @nt_headers.optional_headers.size_of_stack_reserve              = rawfile[(fh_offset + 72)..(fh_offset + 75)]
                    @nt_headers.optional_headers.size_of_stack_commit               = rawfile[(fh_offset + 76)..(fh_offset + 79)]
                    @nt_headers.optional_headers.size_of_heap_reserve               = rawfile[(fh_offset + 80)..(fh_offset + 83)]
                    @nt_headers.optional_headers.size_of_heap_commit                = rawfile[(fh_offset + 84)..(fh_offset + 87)]
                    @nt_headers.optional_headers.loader_flags                       = rawfile[(fh_offset + 88)..(fh_offset + 91)]
                    @nt_headers.optional_headers.number_of_rva_and_sizes            = rawfile[(fh_offset + 92)..(fh_offset + 95)]
                    dd_offset = fh_offset + 96
                    # puts "dd_offset = #{to_c_fmnt_hex(dd_offset)}"

                elsif  @nt_headers.optional_headers.magic == Bytes[0x0B,0x02] # this is for x64 bit binaries 
                    @nt_headers.optional_headers.major_linker_version               = rawfile[(fh_offset + 2)]
                    @nt_headers.optional_headers.minor_linker_version               = rawfile[(fh_offset + 3)]
                    @nt_headers.optional_headers.size_of_code                       = rawfile[(fh_offset + 4 )..(fh_offset + 7 )]
                    @nt_headers.optional_headers.size_of_initialized_data           = rawfile[(fh_offset + 8 )..(fh_offset + 11)]
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
                else 
                    raise "Error Optional Bytes indicate a Non X86 or X64 binary. we cant parse this!!!"
                end 

                # its 16 sets of 2x4 byte chunks so 64 bytes
                16.times do |i|
                    # puts (i*8) + dd_offset 
                    d = ImageDataDirectory.new()
                    d.virtual_address  = rawfile[(dd_offset + (i*8))..(dd_offset + (i*8 + 3))]
                    d.size             = rawfile[(dd_offset + ((i*8) + 4))..(dd_offset + ((i*8) + 7))]

                    case i 
                    when 0 
                        @nt_headers.optional_headers.data_directory.export_directory            = d
                    when 1 
                        @nt_headers.optional_headers.data_directory.import_directory            = d
                    when 2 
                        @nt_headers.optional_headers.data_directory.resource_directory          = d
                    when 3 
                        @nt_headers.optional_headers.data_directory.exception_directory         = d
                    when 4 
                        @nt_headers.optional_headers.data_directory.security_directory          = d
                    when 5 
                        @nt_headers.optional_headers.data_directory.basereloc_directory         = d
                    when 6 
                        @nt_headers.optional_headers.data_directory.debug_directory             = d
                    when 7 
                        @nt_headers.optional_headers.data_directory.architecture_directory      = d
                    when 8 
                        @nt_headers.optional_headers.data_directory.global_ptr_directory        = d
                    when 9 
                        @nt_headers.optional_headers.data_directory.tls_directory               = d
                    when 10 
                        @nt_headers.optional_headers.data_directory.load_config_directory       = d
                    when 11 
                        @nt_headers.optional_headers.data_directory.bound_import_directory      = d
                    when 12 
                        @nt_headers.optional_headers.data_directory.iat_directory               = d
                    when 13 
                        @nt_headers.optional_headers.data_directory.delay_import_directory      = d
                    when 14 
                        @nt_headers.optional_headers.data_directory.com_descriptor_directory    = d
                    when 15 
                        # this one shouldnt exist XD but maybe some day???
                    end 

                end 


                sec_header_offset = dd_offset + ((16*8)) # set up offset based on position +1 of last entry inb data directory 

                # now we parse the section headers
                # Section headers are 40 bytes long
                section_count = IO::ByteFormat::LittleEndian.decode(Int16, @nt_headers.file_headers.number_of_sections.not_nil! )
                section_count.times do |i|
                    t = SectionHeader.new()
                    t.name                      = rawfile[(sec_header_offset + (i*40)       )..(sec_header_offset + (i*40   + 7     ))] # this one is a qword long 
                    t.misc                      = rawfile[(sec_header_offset + ((i*40) + 8 ))..(sec_header_offset + ((i*40) + 8  + 3))] # using the ((i*8) + 8  + 3) schema to easier find and identify words, dwords and qwords while readin the code 
                    t.virtual_address           = rawfile[(sec_header_offset + ((i*40) + 12))..(sec_header_offset + ((i*40) + 12 + 3))]
                    t.size_of_raw_data          = rawfile[(sec_header_offset + ((i*40) + 16))..(sec_header_offset + ((i*40) + 16 + 3))]
                    t.pointer_to_raw_data       = rawfile[(sec_header_offset + ((i*40) + 20))..(sec_header_offset + ((i*40) + 20 + 3))]
                    t.pointer_to_line_numbers   = rawfile[(sec_header_offset + ((i*40) + 24))..(sec_header_offset + ((i*40) + 24 + 3))] 
                    t.number_of_relocations     = rawfile[(sec_header_offset + ((i*40) + 28))..(sec_header_offset + ((i*40) + 28 + 1))]
                    t.number_of_linenumber      = rawfile[(sec_header_offset + ((i*40) + 30))..(sec_header_offset + ((i*40) + 30 + 1))]
                    t.characteristics           = rawfile[(sec_header_offset + ((i*40) + 32))..(sec_header_offset + ((i*40) + 32 + 7))]
                    section_table << t 
                end



                # now we parse the sections themselves
                endoflastsection_offset = 0 
                section_table.each do |header|
                    offset = IO::ByteFormat::LittleEndian.decode(Int32, header.pointer_to_raw_data.not_nil! ) 
                    size   = IO::ByteFormat::LittleEndian.decode(Int32,header.size_of_raw_data.not_nil! ) 
                    # puts "DBG: Size-1: #{size - 1 }"
                    if ( size - 1 ) < 0 
                        section = Bytes[] # this is for the bss section or any section htat doestn have a size 
                    else 
                        endoflastsection_offset = offset + (size )
                        section = rawfile[(offset)..(offset + (size - 1 ) )] 
                    end 


                    # sections[to_c_fmnt_hex( header.name )] = section 
                    sections[String.new(header.name.not_nil!)] = section
                end 


                # now grab the overlay it is the chunk of data at the end of the binary 
                @overlay.bytes = rawfile[endoflastsection_offset..]
                @overlay.offset = endoflastsection_offset









                ########################
                # the below blobs parse each section in the data directory 
                ########################

                # puts "Parsing Export directory"
                # Parse the Export Directory here
                if @nt_headers.optional_headers.data_directory.export_directory.not_nil!.virtual_address.not_nil! != Bytes[0,0,0,0,0,0,0,0] # prob should have an export dir before we parse it XD 

                    # first parse the export dir for info and rvas
                    export_dir_offset = resolve_rva_offset(@nt_headers.optional_headers.data_directory.export_directory.not_nil!.virtual_address.not_nil!)
                    # puts "Export Offset: #{to_c_fmnt_hex(export_dir_offset)}"
                    @img_exp_dir.characteristics              = rawfile[ (export_dir_offset + 0)..(export_dir_offset + 0 + 3 )]      
                    @img_exp_dir.time_date_stamp              = rawfile[ (export_dir_offset + 4)..(export_dir_offset + 4  + 3 )]      
                    @img_exp_dir.major_version                = rawfile[ (export_dir_offset + 8)..(export_dir_offset + 8 + 1 )]      
                    @img_exp_dir.minor_version                = rawfile[ (export_dir_offset + 10)..(export_dir_offset + 10 + 1 )]      
                    @img_exp_dir.name                         = rawfile[ (export_dir_offset + 12)..(export_dir_offset + 12 + 3 )]      
                    @img_exp_dir.base                         = rawfile[ (export_dir_offset + 16)..(export_dir_offset + 16 + 3 )]      
                    @img_exp_dir.number_of_functions          = rawfile[ (export_dir_offset + 20)..(export_dir_offset + 20 + 3 )]      
                    @img_exp_dir.number_of_names              = rawfile[ (export_dir_offset + 24)..(export_dir_offset + 24 + 3 )]      
                    @img_exp_dir.address_of_functions         = rawfile[ (export_dir_offset + 28)..(export_dir_offset + 28 + 3 )]      
                    @img_exp_dir.address_of_names             = rawfile[ (export_dir_offset + 32)..(export_dir_offset + 32 + 3 )]      
                    @img_exp_dir.address_of_name_ordinals     = rawfile[ (export_dir_offset + 36)..(export_dir_offset + 36 + 3 )]      
                    
                    #now resolve the string name of the dll:
                    @img_exp_dir.name_str     = String.new( rawfile[ resolve_rva_offset(@img_exp_dir.name.not_nil!) .. resolve_rva_offset(@img_exp_dir.name.not_nil!) + 100]).split("\x00").first 
                    
                    # now parse out the functions 

                    # these are the base offsets for each of the functions/names/ordinals but those are just arrays of rvas that need to be resolved to get the actual data
                    export_functions_offset = resolve_rva_offset(@img_exp_dir.address_of_functions.not_nil!) 
                    # puts "ExportFuncsOffset: #{to_c_fmnt_hex(export_functions_offset)}"
                    export_name_offset      = resolve_rva_offset(@img_exp_dir.address_of_names.not_nil!)
                    # puts "ExportNameOffset: #{to_c_fmnt_hex(export_name_offset)}"
                    export_addr_name_ord_offset = resolve_rva_offset(@img_exp_dir.address_of_name_ordinals.not_nil!) 
                    # puts "ExportOrdOffset: #{to_c_fmnt_hex(export_addr_name_ord_offset)}"
                    # puts "" 

                    # we loop through the export name table and populate the @exports list of function exported by our dll
                    IO::ByteFormat::LittleEndian.decode(Int32,@img_exp_dir.number_of_functions.not_nil!).times do |i| 

                        ef = ExportedFunction.new() # new export function object 
                        
                        # now we set the index of it as all functions will have an index
                        ef.index = i 
                        ef.ordinal = i + IO::ByteFormat::LittleEndian.decode(Int32,@img_exp_dir.base.not_nil!) # while this is technically correct it is missleading
                        ef.function_rva = IO::ByteFormat::LittleEndian.decode(Int32, rawfile[ export_functions_offset + (i * 4 ) .. export_functions_offset + (i * 4 ) + 3 ] )

                        # now we loop through all the name offsets to find the correct name..... with the associated ordinal  
                        IO::ByteFormat::LittleEndian.decode(Int32,@img_exp_dir.number_of_names.not_nil!).times do |i_f|
                            # ef.ordinal = i + IO::ByteFormat::LittleEndian.decode(Int32,@img_exp_dir.base.not_nil!) # this will always be the case
                            # the address of our curently selected name offset? 
                            # ex_name_offset   = resolve_rva_offset(rawfile[ ( export_name_offset + (i*4)          )..( export_name_offset +          (i*4) + 3 ) ] )

                            ex_name_offset   = resolve_rva_offset(rawfile[ ( export_name_offset + (i_f*4)          )..( export_name_offset +          (i_f*4) + 3 ) ] )
                            # pp ex_name_offset
                            name_ord = IO::ByteFormat::LittleEndian.decode(Int16, rawfile[ ( export_addr_name_ord_offset + (i_f*2) )..( export_addr_name_ord_offset + (i_f*2) + 1 ) ] )
                            # pp name_ord

                            if ef.ordinal - IO::ByteFormat::LittleEndian.decode(Int32,@img_exp_dir.base.not_nil!)  == name_ord
                                ef.name_rva = IO::ByteFormat::LittleEndian.decode(Int32,
                                                        rawfile[export_name_offset + (i_f * 4 ) .. export_name_offset + (i_f * 4 ) + 4] # the bytes of our name rva 
                                )
                                ef.name = String.new( rawfile[( ex_name_offset )..( ex_name_offset +  100)] ).split("\x00").first  

                            end 



                        end 
                        
                        # now we have to check if the thing poited to by our ordinal 




                        ex_func_offset   = resolve_rva_offset(rawfile[ ( export_functions_offset + (i*4)     )..( export_functions_offset +     (i*4) + 3 ) ] )

                        # our function might not be exported by name and therefor the indexing of the lines wont be the same so we need to do a lookup based on the pointer to the address. 
                        
                        
                        ex_addr_name_ord = resolve_rva_offset(rawfile[ ( export_addr_name_ord_offset + (i*4) )..( export_addr_name_ord_offset + (i*4) + 3 ) ] )
                        
                        fn_rva_bytes = rawfile[ ( export_name_offset + (i*4) )..( export_name_offset + (i*4) + 3 ) ]




                        @exports << ef 
                    end


                end 
                # end of parsing export directory 
                # puts "Done Parsing Export Dir"








                # Parse the Import Directory here
                # puts "Parsing Import Dir"
                # import addresses are parsed from the ImageImportDescriptors
                img_imp_desc_offset = resolve_rva_offset(@nt_headers.optional_headers.data_directory.import_directory.not_nil!.virtual_address.not_nil!)

                # puts "IAT Offset: #{to_c_fmnt_hex(iat_offset)}"
                # image import descriptors are 20 bytes in size 
                # we parse the iat by looping untill we find a completely null import descriptor
                while true 
                    # create the imported info record for the iat. we will update the names of functions later
                    ii = ImportedInfo.new()

                    # just the imageimportdescriptor for now 
                    id = ImageImportDescriptor.new()

                    # this is not parsing the whole iat.. just the ImageImportDescriptors which is a lookup table for what dlls are actually going to be loaded
                    id.originalfirstthunk = rawfile[(img_imp_desc_offset + ((@iat.size * 20) + 0 ))..(img_imp_desc_offset + ((@iat.size * 20)  + 0   + 3 ))]
                    id.time_date_stamp    = rawfile[(img_imp_desc_offset + ((@iat.size * 20) + 4 ))..(img_imp_desc_offset + ((@iat.size * 20)  + 4   + 3 ))]
                    id.forwarder_chain    = rawfile[(img_imp_desc_offset + ((@iat.size * 20) + 8 ))..(img_imp_desc_offset + ((@iat.size * 20)  + 8   + 3 ))]
                    id.name               = rawfile[(img_imp_desc_offset + ((@iat.size * 20) + 12))..(img_imp_desc_offset + ((@iat.size * 20)  + 12  + 3 ))]
                    id.first_thunk        = rawfile[(img_imp_desc_offset + ((@iat.size * 20) + 16))..(img_imp_desc_offset + ((@iat.size * 20)  + 16  + 3 ))]

                    if id.name == Bytes[0,0,0,0] && id.first_thunk == Bytes[0,0,0,0]
                        break 
                    end 

                    # add the importdescriptor to our importedinfo object 
                    ii.image_import_descriptor = id 
                    # add the record to the iat array 
                    @iat << ii 
                end 
                # puts "Parsing Import Functions"
                # now load the info for the function in the iat 
                iat.each do |ii| 
                    name_offset = resolve_rva_offset(ii.image_import_descriptor.name.not_nil!)

                    # puts "DLL Name:    #{String.new(rawfile[name_offset..name_offset + 100 ]).split("\x00").first}"
                    # puts "name_offset: #{to_c_fmnt_hex( name_offset )}"
                    ii.dll_name = String.new(rawfile[name_offset..name_offset + 100 ]).split("\x00").first.to_s
                    puts "parsing: #{ii.dll_name}"
                    # get the import lookup table address/offset 
                    ilt_offset = resolve_rva_offset(ii.image_import_descriptor.originalfirstthunk.not_nil!)
                    # puts "ILT offset: #{to_c_fmnt_hex IO::ByteFormat::LittleEndian.decode(Int32,ii.image_import_descriptor.originalfirstthunk.not_nil!) }"


                    # now we loop through the import lookup table to find the addresses of all the imported function names and data
                    # for 32 bit binaries the ilt is an array of 32 bit ints, for 64 bit its 64 bit ints 
                    if is32bit?
                        # this starts at the first spot of 
                        # iibn = rawfile[]
                        # we loop over 32 bit blocks until we hit a 0000 block signifying we are done 
                        # i = 0 # we need a counter for all of our lookups... oh wait... no we dont
                        while true
                            bts = rawfile[(ilt_offset + (ii.functions.size * 4))..(ilt_offset + (ii.functions.size * 4) + 3) ]
                            # this means we hit the end of the table 
                            if bts == Bytes[0,0,0,0] 
                                break 
                            end
                            # i += 1 

                            # puts " First Bytes of #{to_c_fmnt_hex(bts)}"
                            # if the last item is 0 then its using a hint/table so we need to look up the adress of the first 2 bytes
                            if bts.last == 0
                                iibn_offset = resolve_rva_offset(bts) 
                                iibn = ImageImportByName.new()
                                iibn.hint = rawfile[(iibn_offset)..(iibn_offset+1)] # first 2 bytes are the hint 
                                iibn.name = String.new(rawfile[(iibn_offset+2)..(iibn_offset+100)]).split("\x00").first
                                ii.functions << iibn
                            else # otherwise its being called directly by its ordinal
                                # puts "bts.last is not 0"
                                iibo = ImageImportByOrdinal.new()
                                iibo.ordinal = IO::ByteFormat::LittleEndian.decode(UInt16, bts[0..1])
                                ii.functions << iibo
                            end 
                            # x = gets 

                            # puts "starting over?"
                        end 
                        # puts "End of parsing iat?"
                        
                    elsif is64bit? 
                        while true
                            bts = rawfile[(ilt_offset + (ii.functions.size * 8))..(ilt_offset + (ii.functions.size * 8) + 7) ]
                            
                            # this means we hit the end of the table (kinda)
                            if bts == Bytes[0,0,0,0,0,0,0,0] 
                                break 
                            else 
                                # puts "DBG:[ImpFuncTab]: #{to_c_fmnt_hex(bts)} "
                                # gets 
                            end
                            # i += 1 

                            # puts " First Bytes of #{to_c_fmnt_hex(bts)}"
                            # if the last item is 0 then its using a hint/table so we need to look up the adress of the first 2 bytes
                            if bts.last == 0
                                # puts "bts.last is 0"
                                iibn_offset = resolve_rva_offset(bts[0..3]) # this needs to be only the first dword for the address lookup 
                                iibn = ImageImportByName.new()
                                iibn.hint = rawfile[(iibn_offset)..(iibn_offset+1)] # first 2 bytes are the hint 
                                iibn.name = String.new(rawfile[(iibn_offset+2)..(iibn_offset+100)]).split("\x00").first # its a name... so use the first null byte to terminate and use that 
                                ii.functions << iibn

                            else # otherwise its being called directly by its ordinal
                                # puts "bts.last is not 0"
                                iibo = ImageImportByOrdinal.new()
                                iibo.ordinal = IO::ByteFormat::LittleEndian.decode(UInt16, bts[0..1])
                                ii.functions << iibo
                            end 
                            # x = gets 

                            # puts "starting over?"
                        end 
                    else 
                        raise "somehow we made it here without already checking bitting.... HOW?"
                    end 

                    # iibn.hint = rawfile[]
                    # iibn.name = 


                    # ii.import_names << iibn 
                end
                # puts "Done Parsing Import Dir"

                # end of parsing Import directory 






                # Parse the Resource Directory here
                # end of parsing Resource directory 

                # Parse the Exception Directory here
                # end of parsing Exception Directory 

                # Parse the Security Directory here
                # end of parsing Security Directory 

                # Parse the Debug Directory here
                # end of parsing Debug  Directory 

                # Parse the Architecture Specific Directory here
                # end of parsing Architecture Specific Directory 

                # Parse the RVA of Global Ptr Directory here
                # end of parsing RVA of Global Ptr Directory 

                # Parse the TLS Directory here
                # end of parsing TLS  Directory 

                # Parse the Load Config Directory here
                # end of parsing Load Config  Directory 

                # Parse the Bound Import Directory here
                # end of parsing  Bound Import Directory 

                # Parse the IAT Directory here
                # end of parsing IAT  Directory 

                # Parse the Delayed Load Import Directory here
                # end of parsing Delayed Load Import  Directory 

                # Parse the .NET Directory here
                # end of parsing .NET Directory 






            # puts "End of parsing!"
        end 




        # calculate the rva file offset by looping through the sections and finding the section where the iat lives
        # returns the file offset in an int32 object of th
        def resolve_rva_offset(rva : Bytes) : Int32 
            init_rva = IO::ByteFormat::LittleEndian.decode(Int32, rva ) 
            # puts "IAT_RVA: #{nit_rva}"
            ret_offset = 0

            section_table.each_with_index do |sec, i | 
                # if our iat rva is in this section return its index 
                sec_va      = IO::ByteFormat::LittleEndian.decode(Int32, sec.virtual_address.not_nil!)
                # puts "Sec_va:#{to_c_fmnt_hex( sec_va      ) }"
                sec_misc_va = IO::ByteFormat::LittleEndian.decode(Int32,sec.misc.not_nil!)
                # puts "Sec_misc:#{to_c_fmnt_hex( sec_misc_va ) }"
                sec_ptr_raw = IO::ByteFormat::LittleEndian.decode(Int32,sec.pointer_to_raw_data.not_nil!)
                # puts "Sec_ptr:#{to_c_fmnt_hex( sec_ptr_raw ) }"

                # puts "iat_rva(#{to_c_fmnt_hex(iat_rva)}) >= sec_va(#{to_c_fmnt_hex( sec_va      )})" if (iat_rva >= sec_va )
                # puts "iat_rva(#{to_c_fmnt_hex(iat_rva)}) < sec_misc_va(#{to_c_fmnt_hex( sec_misc_va      )}) + sec_va(#{to_c_fmnt_hex( sec_va      )})" if (iat_rva < sec_misc_va + sec_va)


                if(init_rva >= sec_va ) && (init_rva < sec_misc_va +  sec_va )
                    ret_offset = (init_rva - sec_va ) + sec_ptr_raw
                    break 
                end 
            end 
            return ret_offset 
        end 

        # this function updates the dos stub by replacing the parsed section with the supplied bytes. 
        # it also updates the offsets of the file so it still works correctly. 
        # This preserves the rich header if there is one. 
        def update_dos_stub(bytes : Bytes )

        end 


        def insert_rich_header(newheader : RichHeader )

        end 
        

        def update_rich_header(newheader : RichHeader)

        end 

        def insert_section(bytes : Bytes ) 
        end 


        # this function strips out the overlay function from the end of the binary 
        def strip_overlay()
            @overlay.bytes = Bytes[]
        end 




        # if you edit the structure of a pe at all the checksums will be different and need to be updated. 
        # this should be called manually after making changes before the file is written or used as a whole after changes
        def update_checksum!()
            @nt_headers.optional_headers.check_sum = calculate_checksum()
        end 


        # calculates and returns a le formatted checksum of the file. 
        # in theory this should be the same as the optional header checksum
        def calculate_checksum() : Bytes 
            checksum  = 0_u64
            # max = Math.exp2(32)
            max = 0x100000000_u64
            current_dword = 0_u32

            # create a copy of our image in memory to loop over 
            # this isnt actually a thing...
            # if @overlay.offset > 0 
            #     # puts "Stopping prior to the overlay"
            #     temp = to_slice()# [..@overlay.offset - 1 ]
            # else 
            #     temp = to_slice()
            # end 
            temp = to_slice()
            sze = temp.size 

            if temp.size % 4 != 0 
                # allign to 4
                # puts "Not Aligned to 4 bytes... adding padding"
                temp = (String.new(temp) + "\0"*(4 - (temp.size % 4))).to_slice
            else 
                # puts "Aligned to 4 bytes!"
            end

            # puts "Temp.size(#{temp.size})/4 : #{temp.size / 4 }"
           
            (temp.size / 4 ).to_i.times do |i|
                # print "DBG: [#{ to_c_fmnt_hex  temp[i*4..i*4+3]}]"
                # puts "DBG:[i:#{i}]:: #{checksum} "
                if i == ((@nt_headers.optional_headers.optional_offset + 64) / 4)# 64 is the checksum offset in the opt headers
                    # puts "hit our previous checksum: #{to_c_fmnt_hex temp[i*4..i*4 + 3] }"
                    # puts " < Original CheckSum"
                    # puts "Skipping Original Checksum: #{to_c_fmnt_hex IO::ByteFormat::LittleEndian.decode(UInt32,temp[(i*4)..(i*4 + 3)])} : #{to_c_fmnt_hex(temp[(i*4)..(i*4 + 3)])}"
                    next 
                end
                
                current_dword = IO::ByteFormat::LittleEndian.decode(UInt32,temp[(i*4)..(i*4 + 3)])
                # puts "DWORD: #{current_dword}"
                
                checksum = (checksum & 0xFFFFFFFF) + current_dword.to_u64 + (checksum >> 32)
                if checksum > max 
                    checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
                end 
            end

            # puts "Checksum: #{checksum}"
            checksum = (checksum & 0xFFFF) + (checksum >> 16 )
            # puts "After first hit: #{checksum}"
            checksum = checksum + (checksum >> 16)
            # puts "And second: #{checksum}"
            checksum = checksum & 0xFFFF
            
            # now add the original size (minus padding) to the checksum 
            checksum = checksum + sze 

            checksum = checksum.to_u32
            # puts "New Checksum in hex: 0x#{to_c_fmnt_hex checksum}"
            # puts "New Checksum in dec: #{ checksum}"

            # this is downright awful(but it works XD)... :( do better 
            io = IO::Memory.new() 
            io.write_bytes(checksum)
            return io.to_slice
        end 



        ###################################
        # These functions will compute
        # some basic info about the file 
        # or the bytes supplied 
        ###################################
        def has_exports? 
            if !@img_exp_dir.number_of_functions.nil?  
                if IO::ByteFormat::LittleEndian.decode(Int32, @img_exp_dir.number_of_functions.not_nil!) > 0 
                    return true 
                end 
            end 
            return false 
        end 

        # returns if the file parsed is x64 
        def is64bit? : Bool 
            return @nt_headers.optional_headers.magic == Bytes[0x0B,0x02]
        end

        # returns if the file parsed is x86 
        def is32bit? : Bool 
            return @nt_headers.optional_headers.magic == Bytes[0x0B,0x01]
        end

        # returns a numeric shannon entropy value
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

        # returns a numeric shannon entropy value of the given bytes
        def shannon_entropy(data : Bytes ) : Float64 
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



        # outputs the md5sum of the file 
        def md5 : Bytes 
            d = Digest::MD5.new()
            d << rawfile 
            return d.final
        end 

        # returns the md5sum bytes of the supplied bytes 
        def md5(bytes : Bytes ) : Bytes 
            d = Digest::MD5.new()
            d << bytes
            return d.final
        end 

        # outputs the sha256sum of the file
        def sha256 : Bytes 
            d = Digest::SHA256.new()
            d << rawfile 
            return d.final
        end
        
        # returns the sha256sum bytes of the supplied bytes 
        def sha256(bytes : Bytes ) : Bytes 
            d = Digest::SHA256.new()
            d << bytes
            return d.final
        end 
        
        # outputs the sha1sum of the file
        def sha1 : Bytes 
            d = Digest::SHA1.new()
            d << rawfile 
            return d.final
        end
        
        # returns the sha1sum bytes of the supplied bytes 
        def sha1(bytes : Bytes ) : Bytes 
            d = Digest::SHA1.new()
            d << bytes
            return d.final
        end 
        
        # outputs the sha512sum of the file
        def sha512 : Bytes 
            d = Digest::SHA512.new()
            d << rawfile 
            return d.final
        end
        
        # returns the sha512sum bytes of the supplied bytes 
        def sha512(bytes : Bytes ) : Bytes 
            d = Digest::SHA512.new()
            d << bytes
            return d.final
        end 


    end 
end