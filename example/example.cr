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
    :ntheaders => false,
    :optional_headers => false, 
    :data_dirs => false, 
    :section_headers => false, 
    :section_raw => false, 
    :iat => false, 
    :eat => false, 
    :fileinfo => false,
    :new_file => false 
}

filename = "-"

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

    opts.on("--new-file", "Writes the modified file to the specified filename") do 
        options[:new_file] = true 
    end 

    



    
        
    

    opts.separator("Misc: ")
    opts.on("-h", "--help", "Prints help menu") do 
        puts opts
        exit 
    end 

end.parse()

begin 
    if filename == "-"
        ff = STDIN.getb_to_end()
        pefile = CrystalPE::PE_File.new(ff)
    else 
        pefile = CrystalPE::PE_File.new(filename)
    end 
rescue e 
    puts e.message
    puts "\nParsing error! Is the file actually a PE file?"
    exit 1 
    pefile = CrystalPE::PE_File.new # base initiate should get us there we are exiting before this anyways XD 
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
        puts "    > Section: #{String.new(header.name.not_nil!) unless header.name.nil?}"
        puts "        > Name: #{ to_c_fmnt_hex( header.name ) }"
        puts "        > Misc(vsize/physaddr): #{ to_c_fmnt_hex( header.misc ) }"
        puts "        > VirtualAddress: #{ to_c_fmnt_hex( header.virtual_address ) } : #{to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.virtual_address.not_nil!) )}"
        puts "        > Size of Raw Data: #{ to_c_fmnt_hex( header.size_of_raw_data ) } : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.size_of_raw_data.not_nil! ) )}"
        puts "        > Ptr to Raw Data: #{ to_c_fmnt_hex( header.pointer_to_raw_data ) } : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int32,header.pointer_to_raw_data.not_nil!)) }"
        puts "        > # of Relocations: #{ to_c_fmnt_hex( header.number_of_relocations ) }  : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,header.number_of_relocations.not_nil!)) }"
        puts "        > # of Linenumbers: #{ to_c_fmnt_hex( header.number_of_linenumber ) }  : #{ to_c_fmnt_hex( IO::ByteFormat::LittleEndian.decode(Int16,header.number_of_linenumber.not_nil! ) ) }"
        puts "        > Characteristics: #{ to_c_fmnt_hex( header.characteristics ) }"
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

if options[:new_file]
    puts "Stripping Overlay..."
    pefile.strip_overlay()

    # puts "Updating checksum... not that it would change as the overlay isnt used to calculate it XD"
    pefile.update_checksum!()
    
    puts "Writing File to 'newfile.exe'"
    # pefile.write("newfile.exe")
    File.write("newfile.exe", pefile.to_slice )
end 