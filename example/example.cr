require "../src/crystalpe"

require "option_parser"

# some quick hex printable functions 

def to_c_fmnt_hex( data : Bytes | Nil   )
    return "" if data.nil? 
    io = IO::Memory.new() 
        data.as(Bytes).each do |d| 
            io.printf("%02X", d )
        end
    return io.to_s 
end

def to_c_fmnt_hex( data : UInt8|UInt16|UInt32|UInt64|UInt128|Int8|Int16|Int32|Int64|Int128|Nil)
    return "" if data.nil? 
    io = IO::Memory.new() 
    io.printf("%02X", data )
    return io.to_s 
end




# set up our option parsing 
options = {
    :dos => false,
    :rich_headers => false, 
    :ntheaders => false,
    :optional_headers => false, 
    :data_dirs => false, 
    :section_headers => false, 
    :section_raw => false, 
    :iat => false, 
    :eat => false, 
    :fileinfo => false,
    :new_file => false, 
    :new_dos_stub => false ,
    :strings => false,
    :dump_overlay => false, 
    :dot_net_info => false,

    :verbosity_1 => false, 
    :verbosity_2 => false, 
    :verbosity_3 => false, 
    :verbosity_4 => false, 
    :verbosity_5 => false, 
}

filename = "-"
overlay_dump_filename = ""
new_file_path = "newfile.exe"
dos_stub = Bytes[] 
Log.setup(:warn)

parser = OptionParser.new() do |opts| 
    opts.banner = "x86/x64 Windows PE File parser\nBy: CausticKirbyZ"
    
    opts.on("-f", "--file=[file]","The File to parse") do |file|
        if file == "-"
            # get it from stdin 
            puts "Starting reading from stdin mode..."
        else 
            filename = file 
        end
    end

    opts.separator("Optional args: ")
    opts.on("-d", "--dos", "Shows breakdown of DOS Header") do 
        options[:dos] = true 
    end 
    opts.on("--rich", "Shows breackdown of Rich Headers") do 
        options[:rich_headers] = true 
    end 
        
    opts.on("-n", "--nt-headers", "Shows breakdown of NT Headers") do 
        options[:ntheaders] = true 
    end 
        
    opts.on("--nt-optional", "Shows breakdown of NT Optional Headers") do 
        options[:optional_headers] = true 
    end  

    opts.on("--data-dir", "Shows breakdown of data directory") do 
        options[:data_dirs] = true 
    end 

    opts.on("-s","--section-headers", "Shows breakdown of the Section Headers ") do 
        options[:section_headers] = true 
    end 

    opts.on("--section-raw", "Shows raw information of each section") do 
        options[:section_raw] = true 
    end 

    opts.on("-i","--iat", "Shows raw information of the Import Address Table") do 
        options[:iat] = true 
    end 

    opts.on("-e","--eat", "Shows information from the Export Address Table") do 
        options[:eat] = true 
    end 

    opts.on("--info", "Shows information Generic info about the file") do 
        options[:fileinfo] = true 
    end 

    opts.on("--new-file=[filename]", "Writes the modified file to the specified filename") do |fname|
        options[:new_file] = true 
        new_file_path = fname
    end 

    opts.on("--new-dos-stub=[filename]", "Writes the modified file to the specified filename") do |dosfilename|
        options[:new_dos_stub] = true 
        dos_stub = File.read(dosfilename).to_slice 
    end 

    opts.on("--strings", "Prints the output of 'Strings'. Array of strings >= 4 ascii chars long") do 
        options[:strings] = true 
    end 

    opts.on("--dump-overlay=[filename]", "Dumps the raw contents of the overlay to the file specified") do |fname| 
        options[:dump_overlay] = true 
        overlay_dump_filename = fname
    end 

    opts.on("--dot-net-info", "Dumps the raw contents of the overlay to the file specified") do 
        options[:dot_net_info] = true 
    end 

    opts.on("-v", "Verbosity level 1") do
        options[:verbosity_1] = true 
    end 

    opts.on("-vv", "Verbosity level 2") do
        options[:verbosity_2] = true 
    end 

    opts.on("-vvv", "Verbosity level 3") do
        options[:verbosity_3] = true 
    end 

    opts.on("-vvvv", "Verbosity level 4") do
        options[:verbosity_4] = true 
    end 

    opts.on("-vvvvv", "Verbosity level 5") do
        options[:verbosity_5] = true 
    end 




    
        
    

    opts.separator("Misc: ")
    opts.on("-h", "--help", "Prints help menu") do 
        puts opts
        exit 
    end 

end.parse()


if options[:verbosity_1]
    Log.setup(:warn)
end 
if options[:verbosity_2]
    Log.setup(:notice)
end 
if options[:verbosity_3]
    Log.setup(:info)
end 
if options[:verbosity_4]
    Log.setup(:debug)
end 
if options[:verbosity_5]
    Log.setup(:trace)
end 


begin 
    if filename == "-"
        ff = STDIN.getb_to_end()
        pefile = CrystalPE::PEFile.new(ff)
    else 
        pefile = CrystalPE::PEFile.new(filename)
    end 
rescue e 
    puts e.message
    puts "\nParsing error! Is the file actually a PE file?"
    exit 1 
    pefile = CrystalPE::PEFile.new # base initiate should get us there we are exiting before this anyways XD 
end 

if options[:dos]
    puts "DOS Header: "
    puts "> Magic: #{to_c_fmnt_hex(pefile.dos_header.e_magic.not_nil!)}"
    puts "> e_cplp: #{to_c_fmnt_hex(pefile.dos_header.e_cblp.not_nil!)}"
    puts ""
end 

if options[:ntheaders]
    puts "NT Headers:"
    puts "> Signature: #{to_c_fmnt_hex( pefile.nt_headers.signature) }"
    puts "> File Headers: "
    puts "    > Machine: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.machine) }"
    puts "    > Section Count: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.number_of_sections)}"
    puts "    > TimeDateStamp: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.time_date_stamp)}"
    puts "    > Ptr to Symbol Table: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.pointer_to_symbol_table)}"
    puts "    > Num of Symbols: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.number_of_symbols)}"
    puts "    > Size of OptionalHeader: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.size_of_optional_header)}"
    puts "    > Characteristics: #{to_c_fmnt_hex( pefile.nt_headers.file_headers.characteristics)}"
    puts ""
end 



if options[:rich_headers]
    if pefile.rich_header 
        puts "Rich Headers: "
        puts "Raw(peformatted): #{ to_c_fmnt_hex pefile.rich_header.not_nil!.to_pe_slice() }"
        puts "Raw(unencrypted): #{ to_c_fmnt_hex pefile.rich_header.not_nil!.to_slice() }"
        # pp pefile.rich_header
        puts "> DanS:               #{to_c_fmnt_hex pefile.rich_header.not_nil!.dans_id } | #{String.new pefile.rich_header.not_nil!.dans_id}" # print the hex and the cleartext of this 
        puts "> checksum1:          #{to_c_fmnt_hex pefile.rich_header.not_nil!.checksum_pad1 }"
        puts "> checksum2:          #{to_c_fmnt_hex pefile.rich_header.not_nil!.checksum_pad2 }"
        puts "> checksum3:          #{to_c_fmnt_hex pefile.rich_header.not_nil!.checksum_pad3 }"
        pefile.rich_header.not_nil!.comp_ids.each do |cid| 
            puts "    > Value:   #{cid.build_id}.#{cid.prod_id}.#{cid.count} | #{ to_c_fmnt_hex CrystalPE::RichHeader.xor_crypt( cid.to_slice, pefile.rich_header.not_nil!.xor_key ) }"
            puts "        > BuildID:   #{cid.build_id}"
            puts "        > ProdID:    #{cid.prod_id} | #{cid.prod_id_string}"
            puts "        > Count:     #{cid.count}"
            puts "        > VS Ver:    #{cid.prod_id_vs_version}"
        end 
        puts "> Rich ID:            #{to_c_fmnt_hex pefile.rich_header.not_nil!.rich_id} | #{String.new(pefile.rich_header.not_nil!.rich_id)}" # print the hex and cleartext of this 
        puts "> Parsed Cecksum:     #{ to_c_fmnt_hex pefile.rich_header.not_nil!.xor_key }"
        puts "> Padding:            #{ to_c_fmnt_hex pefile.rich_header.not_nil!.padding }"
        # puts "> Calculated Cecksum: #{}"
    else
         puts "No Rich Header Detected!"
    end 
end 


if options[:optional_headers]
    puts "> Optional Headers: "
    puts "    > Magic: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.magic)}"
    puts "    > Major Linker Version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.major_linker_version)}"
    puts "    > Minor Linker Version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.minor_linker_version)}"
    puts "    > Size of Code: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_code    )}"
    puts "    > size_of_initialized_data: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_initialized_data    )}"
    puts "    > size_of_uninitialized_data: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_uninitialized_data    )}"
    puts "    > address_of_entry_point: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.address_of_entry_point    )}"
    puts "    > base_of_code: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.base_of_code    )}"
    if pefile.is32bit? 
        puts "    > base_of_data: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.base_of_data    )}" 
    end 
    puts "    > image_base: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.image_base    )}"
    puts "    > section_alignment: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.section_alignment    )}"
    puts "    > file_alignment: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.file_alignment    )}"
    puts "    > major_operating_system_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.major_operating_system_version    )}"
    puts "    > minor_operating_system_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.minor_operating_system_version    )}"
    puts "    > major_image_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.major_image_version    )}"
    puts "    > minor_image_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.minor_image_version    )}"
    puts "    > major_subsystem_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.major_subsystem_version    )}"
    puts "    > minor_subsystem_version: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.minor_subsystem_version    )}"
    puts "    > win32_version_value: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.win32_version_value    )}"
    puts "    > size_of_image: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_image    )}"
    puts "    > size_of_headers: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_headers    )}"
    puts "    > check_sum: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.check_sum    )}"
    puts "    > subsystem: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.subsystem    )}"
    puts "    > dll_characteristics: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.dll_characteristics    )}"
    puts "    > size_of_stack_reserve: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_stack_reserve    )}"
    puts "    > size_of_stack_commit: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_stack_commit    )}"
    puts "    > size_of_heap_reserve: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_heap_reserve    )}"
    puts "    > size_of_heap_commit: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.size_of_heap_commit    )}"
    puts "    > loader_flags: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.loader_flags    )}"
    puts "    > number_of_rva_and_sizes: #{to_c_fmnt_hex( pefile.nt_headers.optional_headers.number_of_rva_and_sizes    )}"
    puts ""
end 

if options[:data_dirs]
    puts "    > Data Directories: "
    puts "        > Export Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.export_directory.not_nil!.virtual_address ) }  #{         to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.export_directory.not_nil!.size ) }"
    puts "        > Import Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.import_directory.not_nil!.virtual_address ) } #{         to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.import_directory.not_nil!.size ) }"
    puts "        > Resource Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.resource_directory.not_nil!.virtual_address ) } #{       to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.resource_directory.not_nil!.size ) }"
    puts "        > Exception Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.exception_directory.not_nil!.virtual_address ) } #{      to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.exception_directory.not_nil!.size ) }"
    puts "        > Security Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.security_directory.not_nil!.virtual_address ) } #{       to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.security_directory.not_nil!.size ) }"
    puts "        > BaseReloc Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.basereloc_directory.not_nil!.virtual_address ) } #{      to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.basereloc_directory.not_nil!.size ) }"
    puts "        > Debug Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.debug_directory.not_nil!.virtual_address ) } #{          to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.debug_directory.not_nil!.size ) }"
    puts "        > Architecture Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.architecture_directory.not_nil!.virtual_address ) } #{   to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.architecture_directory.not_nil!.size ) }"
    puts "        > Glob PTR Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.global_ptr_directory.not_nil!.virtual_address ) } #{     to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.global_ptr_directory.not_nil!.size ) }"
    puts "        > TLS Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.tls_directory.not_nil!.virtual_address ) } #{            to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.tls_directory.not_nil!.size ) }"
    puts "        > LoadConfig Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.load_config_directory.not_nil!.virtual_address ) } #{    to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.load_config_directory.not_nil!.size ) }"
    puts "        > Bound Import Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.bound_import_directory.not_nil!.virtual_address ) } #{   to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.bound_import_directory.not_nil!.size ) }"
    puts "        > IAT Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.iat_directory.not_nil!.virtual_address ) } #{            to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.iat_directory.not_nil!.size ) }"
    puts "        > Delay Import Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.delay_import_directory.not_nil!.virtual_address ) } #{   to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.delay_import_directory.not_nil!.size ) }"
    puts "        > COM Desc Directory: #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.com_descriptor_directory.not_nil!.virtual_address ) } #{ to_c_fmnt_hex(pefile.nt_headers.optional_headers.data_directory.com_descriptor_directory.not_nil!.size ) }"
    puts ""
end 

if options[:section_headers]
    puts "> Section Headers: "
    pefile.section_table.each do |header| 
        # puts "    > Section: #{String.new(header.name.not_nil!) unless header.name.nil?}"
        puts "    > Section: #{header.name_as_string unless header.name == 0 }"
        puts "        > Name: #{ to_c_fmnt_hex( header.name ) }"
        puts "        > Misc(vsize/physaddr): #{ to_c_fmnt_hex( header.misc ) }"
        # puts "        > VirtualAddress: #{ to_c_fmnt_hex( header.virtual_address ) } : #{to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.virtual_address.not_nil!) )}"
        # puts "        > Size of Raw Data: #{ to_c_fmnt_hex( header.size_of_raw_data ) } : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.size_of_raw_data.not_nil! ) )}"
        # puts "        > Ptr to Raw Data: #{ to_c_fmnt_hex( header.pointer_to_raw_data ) } : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.pointer_to_raw_data.not_nil!)) }"
        # puts "        > # of Relocations: #{ to_c_fmnt_hex( header.number_of_relocations ) }  : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,header.number_of_relocations.not_nil!)) }"
        # puts "        > # of Linenumbers: #{ to_c_fmnt_hex( header.number_of_linenumber ) }  : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,header.number_of_linenumber.not_nil! ) ) }"
        puts "        > VirtualAddress:   #{ to_c_fmnt_hex( header.virtual_address )        } : #{ to_c_fmnt_hex( header.virtual_address)        }"
        puts "        > Size of Raw Data: #{ to_c_fmnt_hex( header.size_of_raw_data )       } : #{ to_c_fmnt_hex( header.size_of_raw_data )      }"
        puts "        > Ptr to Raw Data:  #{ to_c_fmnt_hex( header.pointer_to_raw_data )    } : #{ to_c_fmnt_hex( header.pointer_to_raw_data)    }"
        puts "        > # of Relocations: #{ to_c_fmnt_hex( header.number_of_relocations )  } : #{ to_c_fmnt_hex( header.number_of_relocations)  }"
        puts "        > # of Linenumbers: #{ to_c_fmnt_hex( header.number_of_linenumber )   } : #{ to_c_fmnt_hex( header.number_of_linenumber )  }"
        puts "        > Characteristics:  #{ to_c_fmnt_hex( header.characteristics ) }"
    end 
    puts ""
end 
if options[:section_raw]
    puts "> Section Raw: "
    pefile.sections.each do |k,v| 
        puts "    > Section: #{k}"
        puts "        > Value: #{to_c_fmnt_hex(v)[0..32]}...#{to_c_fmnt_hex(v)[-32..]}"
        puts "        > Section Entropy: #{pefile.shannon_entropy(v)}"
        puts "        > Section Size: #{v.size} Bytes"
        puts "        > MD5 Sum: #{to_c_fmnt_hex(pefile.md5(v))} "
    end 
    puts ""
end 

if options[:iat]
    puts "> IAT: "
    pefile.iat.each do |import| 
        puts "    > Name: #{import.dll_name}"
        import.functions.each do |f| 
            puts "        > Name: #{f.name} | Ord: #{to_c_fmnt_hex( f.as(CrystalPE::ImageImportByOrdinal).ordinal) if f.class == CrystalPE::ImageImportByOrdinal}"
        end 
    end
    puts ""
end 

if options[:eat]
    if pefile.has_exports?
        puts "> Exports: "
        puts "    > Characteristics: #{      to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.characteristics.not_nil! ) ) }"
        puts "    > DateTimeStamp: #{        to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.time_date_stamp.not_nil! ) ) }"
        puts "    > Major Version: #{        to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,pefile.img_exp_dir.major_version.not_nil! ) ) }"
        puts "    > Minor Version: #{        to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,pefile.img_exp_dir.minor_version.not_nil! ) ) }"
        puts "    > Name: #{                 to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.name.not_nil! ) ) } | #{pefile.img_exp_dir.name_str}"
        puts "    > Base: #{                 to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.base.not_nil! ) ) }"
        puts "    > # of Functions: #{       to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.number_of_functions.not_nil! ) ) }"
        puts "    > # of Names: #{           to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.number_of_names.not_nil! ) ) }"
        puts "    > & of Functions: #{       to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.address_of_functions.not_nil! ) ) }"
        puts "    > & of Names: #{           to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.address_of_names.not_nil! ) ) }"
        puts "    > & of Name Ordinals: #{   to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,pefile.img_exp_dir.address_of_name_ordinals.not_nil! ) ) }"
        puts "    "
        puts "    > Functions: "
        pefile.exports.each do |ex|
            puts "        > #{ex.index}" 
            puts "            > Name:  #{ex.name}" 
            puts "            > Ord:   #{ex.ordinal}"
            puts "            > Index: #{ex.index }"
            puts "            > NameRVA: #{to_c_fmnt_hex(ex.name_rva ) }"
            puts "            > FnctRVA: #{to_c_fmnt_hex(ex.function_rva ) }"
        end 
    end 
end 



if options[:fileinfo]
    puts "File Info: "
    puts "    > Bitting: #{pefile.is64bit? ?  "x64" : "x86"}"
    puts "    > ShannonEntropy: #{pefile.shannon_entropy}"
    puts "    > MD5 Sum: #{to_c_fmnt_hex(pefile.md5)}"
    puts "    > SHA1 Sum: #{to_c_fmnt_hex(pefile.sha1)}"
    puts "    > SHA256 Sum: #{to_c_fmnt_hex(pefile.sha256)}"
    puts "    > SHA512 Sum: #{to_c_fmnt_hex(pefile.sha512)}"
    puts ""
end 

# puts "ImageBase: #{to_c_fmnt_hex(  IO::ByteFormat::LittleEndian.decode(Int64, pefile.nt_headers.optional_headers.image_base.not_nil! ) )}"
# puts "Number of Sections: #{  IO::ByteFormat::LittleEndian.decode(Int16, pefile.nt_headers.file_headers.number_of_sections.not_nil! ) }"

if options[:new_dos_stub]
    puts "Updating Dos Stub..."
    pefile.update_dos_stub!(dos_stub)
    # pefile.update_checksum!
end 





if options[:strings]
    puts "Strings:"
    pefile.strings().each do |str| 
        puts "> #{str}" 
    end 
end 

if options[:dump_overlay]
    if overlay_dump_filename != ""
        puts "Dumping overlay to file: #{overlay_dump_filename}"
        File.write(overlay_dump_filename, pefile.overlay.bytes)
    else 
        puts "Overlay filename cannot be empty/null"
    end 
end 


if options[:dot_net_info]
    if !pefile.dot_net_header.nil?
        puts "DotNetInfo:                            Dec/val | Hex val"
        puts "> Cb:                                  #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.cb                                 }"
        puts "> MajorRuntimeVersion:                 #{ pefile.dot_net_header.not_nil!.major_runtime_version              }"
        puts "> MinorRuntimeVersion:                 #{ pefile.dot_net_header.not_nil!.minor_runtime_version              }"
        puts "> MetaData.va:                         #{ pefile.dot_net_header.not_nil!.meta_data_va                       }"
        puts "> MetaData.size:                       #{ pefile.dot_net_header.not_nil!.meta_data_va                       } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.meta_data_va         }"
        puts "> Flags:                               #{ pefile.dot_net_header.not_nil!.flags                              }"
        puts "> entry_point_token:                   #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.entry_point_token                  }"
        puts "> Resources.va:                        #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.resources_va                       }"
        puts "> Resources.size:                      #{ pefile.dot_net_header.not_nil!.resources_size                     } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.resources_size                     }"
        puts "> StrongNameSignature.va:              #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.strong_name_signature_va           }"
        puts "> StrongNameSignature.size:            #{ pefile.dot_net_header.not_nil!.strong_name_signature_size         } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.strong_name_signature_size         }"
        puts "> CodeManagerTable.va:                 #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.code_manager_table_va              }"
        puts "> CodeManagerTable.size:               #{ pefile.dot_net_header.not_nil!.code_manager_table_size            } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.code_manager_table_size            }"
        puts "> VTableFixups.va:                     #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.v_table_fixups_va                  }"
        puts "> VTableFixups.size:                   #{ pefile.dot_net_header.not_nil!.v_table_fixups_size                 } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.v_table_fixups_size                }"
        puts "> Export_Address_table_jumps.va:       #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.export_address_table_jumps_va     }"
        puts "> Export_Address_TableJumps.size:      #{ pefile.dot_net_header.not_nil!.export_asddress_table_jumps_size    } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.export_asddress_table_jumps_size   }"
        puts "> Manage_native_header_va:             #{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.manage_native_header_va  }"
        puts "> Managed_native_header_size:          #{ pefile.dot_net_header.not_nil!.managed_native_header_size         } | 0x#{ to_c_fmnt_hex pefile.dot_net_header.not_nil!.managed_native_header_size         }"
    end 
end 















if options[:new_file]
    # puts "Stripping Overlay..."
    # pefile.strip_overlay!()

    # dos_stub = Bytes[0,0,0,0]
    # pefile.update_dos_stub!(dos_stub)

    # puts "Updating Rich header..."
    # newheader = CrystalPE::RichHeader.new()
    # set it to be the rich header pulled from win10 notepad.exe 
    # newheader = CrystalPE::RichHeader.from_bytes Bytes[0xA2,0x13,0x95,0x77,0xE6,0x72,0xFB,0x24,0xE6,0x72,0xFB,0x24,0xE6,0x72,0xFB,0x24,0xEF,0x0A,0x68,0x24,0xD6,0x72,0xFB,0x24,0xF2,0x19,0xFF,0x25,0xEC,0x72,0xFB,0x24,0xF2,0x19,0xF8,0x25,0xE5,0x72,0xFB,0x24,0xF2,0x19,0xFA,0x25,0xEF,0x72,0xFB,0x24,0xE6,0x72,0xFA,0x24,0xCE,0x77,0xFB,0x24,0xF2,0x19,0xF3,0x25,0xF9,0x72,0xFB,0x24,0xF2,0x19,0xFE,0x25,0xF9,0x72,0xFB,0x24,0xF2,0x19,0x06,0x24,0xE7,0x72,0xFB,0x24,0xF2,0x19,0x04,0x24,0xE7,0x72,0xFB,0x24,0xF2,0x19,0xF9,0x25,0xE7,0x72,0xFB,0x24,0x52,0x69,0x63,0x68,0xE6,0x72,0xFB,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]
    # pefile.set_rich_header!(newheader)

    

    # puts "Done!"
    # puts "Updating compile time to 10 years ago"
    # pefile.update_compile_time!(Time.local - 10.years )
    
    puts "Updating checksum..."
    pefile.update_checksum!()

    puts "Writing File to 'newfile.exe'"
    # pefile.write("newfile.exe")
    File.write(new_file_path, pefile.to_slice )
    puts "Done!"
end 