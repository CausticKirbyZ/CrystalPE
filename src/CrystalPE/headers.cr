module CrystalPE

    # dos header is a 64 Byte header
    struct DOS_Header
        property e_magic    : Bytes? # = Bytes[0x0]               # Magic number
        property e_cblp     : Bytes? # = Bytes[0x0]               # Bytes on last page of file
        property e_cp       : Bytes? # = Bytes[0x0]               # Pages in file
        property e_crlc     : Bytes? # = Bytes[0x0]               # Relocations
        property e_cparhdr  : Bytes? # = Bytes[0x0]               # Size of header in paragraphs
        property e_minalloc : Bytes? # = Bytes[0x0]               # Minimum extra paragraphs needed
        property e_maxalloc : Bytes? # = Bytes[0x0]               # Maximum extra paragraphs needed
        property e_ss       : Bytes? # = Bytes[0x0]               # Initial (relative) SS value
        property e_sp       : Bytes? # = Bytes[0x0]               # Initial SP value
        property e_csum     : Bytes? # = Bytes[0x0]               # Checksum
        property e_ip       : Bytes? # = Bytes[0x0]               # Initial IP value
        property e_cs       : Bytes? # = Bytes[0x0]               # Initial (relative) CS value
        property e_lfarlc   : Bytes? # = Bytes[0x0]               # File address of relocation table
        property e_ovno     : Bytes? # = Bytes[0x0]               # Overlay number
        property e_res      : Bytes? # = Bytes[0x0]               # Reserved words
        property e_oemid    : Bytes? # = Bytes[0x0]               # OEM identifier (for e_oeminfo)
        property e_oeminfo  : Bytes? # = Bytes[0x0]               # OEM information; e_oemid specific
        property e_res2     : Bytes? # = Bytes[0x0]               # Reserved words
        property e_lfanew   : Bytes? # = Bytes[0x0]               # File address of new exe header
    end


    struct DOS_Stub 
        # property stub 
    end

    struct RichHeader
    end


    struct NT_Headers
        property signature                          : Bytes? 
        property file_headers                       : NTFileHeaders =  NTFileHeaders.new()
        property optional_headers                   : NTOptionalHeaders = NTOptionalHeaders.new()
    end

    struct NTFileHeaders
        property machine                            : Bytes? 
        property number_of_sections                 : Bytes? 
        property time_date_stamp                    : Bytes? 
        property pointer_to_symbol_table            : Bytes? 
        property number_of_symbols                  : Bytes? 
        property size_of_optional_header            : Bytes? 
        property characteristics                    : Bytes? 
    end

    struct NTOptionalHeaders
        property magic                              : Bytes? 
        property major_linker_version               : UInt8? 
        property minor_linker_version               : UInt8? 
        property size_of_code                       : Bytes? 
        property size_of_initialized_data           : Bytes? 
        property size_of_uninitialized_data         : Bytes? 
        property address_of_entry_point             : Bytes? 
        property base_of_code                       : Bytes? 
        property base_of_data                       : Bytes? 
        property image_base                         : Bytes? 
        property section_alignment                  : Bytes? 
        property file_alignment                     : Bytes? 
        property major_operating_system_version     : Bytes? 
        property minor_operating_system_version     : Bytes? 
        property major_image_version                : Bytes? 
        property minor_image_version                : Bytes? 
        property major_subsystem_version            : Bytes? 
        property minor_subsystem_version            : Bytes? 
        property win32_version_value                : Bytes? 
        property size_of_image                      : Bytes? 
        property size_of_headers                    : Bytes? 
        property check_sum                          : Bytes? 
        property subsystem                          : Bytes? 
        property dll_characteristics                : Bytes? 
        property size_of_stack_reserve              : Bytes? 
        property size_of_stack_commit               : Bytes? 
        property size_of_heap_reserve               : Bytes? 
        property size_of_heap_commit                : Bytes? 
        property loader_flags                       : Bytes? 
        property number_of_rva_and_sizes            : Bytes? 
        property data_directory                     : DataDirectory = DataDirectory.new 
    end 

    struct DataDirectory
        property export_directory                   : ImageDataDirectory?
        property import_directory                   : ImageDataDirectory?
        property resource_directory                 : ImageDataDirectory?
        property exception_directory                : ImageDataDirectory?
        property security_directory                 : ImageDataDirectory?
        property basereloc_directory                : ImageDataDirectory?
        property debug_directory                    : ImageDataDirectory?
        property architecture_directory             : ImageDataDirectory?
        property global_ptr_directory               : ImageDataDirectory?
        property tls_directory                      : ImageDataDirectory?
        property load_config_directory              : ImageDataDirectory?
        property bound_import_directory             : ImageDataDirectory?
        property iat_directory                      : ImageDataDirectory?
        property delay_import_directory             : ImageDataDirectory?
        property com_descriptor_directory           : ImageDataDirectory?
    end 

    struct ImageDataDirectory
        property virtual_address                    : Bytes? 
        property size                               : Bytes? 
    end


    struct SectionHeader 
        property name                               : Bytes?
        property misc                               : Bytes? # this is either PhysicalAddress or VirtualSize
        property virtual_address                    : Bytes? 
        property size_of_raw_data                   : Bytes? 
        property pointer_to_raw_data                : Bytes? 
        property pointer_to_line_numbers            : Bytes? 
        property number_of_relocations              : Bytes? 
        property number_of_linenumber               : Bytes? 
        property characteristics                    : Bytes? 
    end



end