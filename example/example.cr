require "../src/crystalpe"


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

pefile = CrystalPE::PE_File.new(ARGV[0])

# pp pefile.dos_header
# pp pefile.nt_headers
#puts  String.new( pefile.dos_header.e_magic.not_nil! )
# printf("%02X %02X\n", pefile.dos_header.e_magic.not_nil![0],pefile.dos_header.e_magic.not_nil![1] )
puts "DOS Header: "
puts "> Magic: #{to_c_fmnt_hex(pefile.dos_header.e_magic.not_nil!)}"
puts "> e_cplp: #{to_c_fmnt_hex(pefile.dos_header.e_cblp.not_nil!)}"

puts ""
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

puts "    > Data Directories: "
# pp pefile.nt_headers.optional_headers
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

puts "> Section Raw: "
pefile.sections.each do |k,v| 
    puts "    > Section: #{k}"
    puts "        > Value: #{to_c_fmnt_hex(v)[0..32]}...#{to_c_fmnt_hex(v)[-32..]}"
    puts "        > Section Entropy: #{pefile.shannon_entropy(v)}"
    puts "        > Section Size: #{v.size} Bytes"
end 
puts "> IAT: "
pefile.iat.each do |import| 
    puts "    > Name: #{import.dll_name}"
    import.functions.each do |f| 
        puts "        > Name: #{f.name}"
    end 
end
















puts "File Info: "
puts "    > Bitting: #{pefile.is64bit? ?  "x64" : "x86"}"
puts "    > ShannonEntropy: #{pefile.shannon_entropy}"
puts "    > MD5 Sum: #{to_c_fmnt_hex(pefile.md5)}"
puts "    > SHA1 Sum: #{to_c_fmnt_hex(pefile.sha1)}"
puts "    > SHA256 Sum: #{to_c_fmnt_hex(pefile.sha256)}"
puts "    > SHA512 Sum: #{to_c_fmnt_hex(pefile.sha512)}"


# puts "ImageBase: #{to_c_fmnt_hex(  IO::ByteFormat::LittleEndian.decode(Int64, pefile.nt_headers.optional_headers.image_base.not_nil! ) )}"
# puts "Number of Sections: #{  IO::ByteFormat::LittleEndian.decode(Int16, pefile.nt_headers.file_headers.number_of_sections.not_nil! ) }"

