module CrystalPE 
    
    
    
    # +===============================+
    # |         .rsrc Section         |
    # +===============================+
    # |   Image Resource Directories  |
    # +-------------------------------+
    # |          Name Strings         | 
    # +-------------------------------+ 
    # |      Resource Data Entries    |
    # +-------------------------------+
    # |         Resource Data         |
    # +-------------------------------+
    # 
    # this is prob gonna be a parent class for easily working with it... maybe?
    # class Resources 
    #     property resource_directory : Image_Resource_Directory = Image_Resource_Directory.new()
        
    #     # this acts as our "parent directory" for all the resources in the file 
    #     # property entries            : Array(Image_Resource_Directory_Entry) = [] of Image_Resource_Directory_Entry
        
    #     property padding            : Bytes = Bytes[] # we will need to keep track of the padding. both in order to write it back and if we want we could change it without affecting the binary strucutre


    #     # this returs the correctly formatted bytes for our .rsrc structure
    #     # the resources are actually a bfs search and must be queues appropriately thus the parent class?
    #     def to_slice  : Bytes 
    #         io = IO::Memory.new()
            
    #         # write our root entry to the io 
    #         io.write (resource_directory.to_slice)

            
    #         # set 4 ios to capture the appropriate byutes for each "data type" then we will write them all at once 
    #         dir_ent_queue = IO::Memory.new # = Deque(Image_Resource_Directory).new 
    #         names_queue   = IO::Memory.new # = Deque(Image_Resource_Directory_String).new 
    #         entry_queue   = IO::Memory.new # = Deque(Image_Resource_Data_Entry).new 
    #         data_queue    = IO::Memory.new # = Deque(Bytes).new 

    #         # we will use a double ended queue for keeping track of where we are and  to order the entries appropriately 
    #         q = Deque(Image_Resource_Directory_Entry).new
            
    #         # push all our children to the queue
    #         entries.each do |e| 
    #             q.push e
    #         end 

    #         # now itterate through the queue and add any children of the entry to the end of the queue while adding the appropriate data to its respective io 
    #         while q.size > 0
    #             # pull the first entry off the queue  
    #             c = q.shift 

    #             # add its data to the correct io
    #             dir_ent_queue.write c.to_slice 

    #             # # now add any children to the queue
    #             # c.children.each do |child| 
    #             #     q << 

    #         end 



            
            
    #         # write the io structures to the main io and then we can return...... lol 
    #         io.write dir_ent_queue 
    #         io.write names_queue   
    #         io.write entry_queue   
    #         io.write data_queue    

    #         #dont forget to write the padding
    #         io.write padding 

    #         return io.to_slice 
    #     end 


    #     # creates a new object from a .rsrc section bytes. 
    #     # as the offsets are only relative to the beginning address of the .rsrc section, they can be parsed easily on their own. 
    #     def initialize(section_bytes : Bytes )

    #         # we initialize our root node 
    #         puts section_bytes[0..15].hexdump
    #         @resource_directory = Image_Resource_Directory.from_bytes(section_bytes[0..15])

    #         entries_offset = 16 # the start of our directory entries
    #         total_resources = @resource_directory.number_of_named_entries + @resource_directory.number_of_id_entries
    #         total_resources.times do |i| 
    #             # create our dir_entry object from the appropriate bytes for the parent node
    #             entry = Image_Resource_Directory_Entry.new(section_bytes[entries_offset + (i*8) .. entries_offset + (8*i) + 7])   
                
    #             # now have the entry recursivly parse its children 
    #             entry.parse_children(section_bytes)

    #             # finally add our item to our entries array 
    #             @entries << entry 
                        
    #         end 


    #     end 


    # end 






    # https://referencesource.microsoft.com/#System.Deployment/System/Deployment/Application/PEStream.cs,b01be218023fc607,references
    class Image_Resource_Directory 
        property characteristics           : UInt32 = 0 
        property time_date_stamp           : UInt32 = 0 
        property major_version             : UInt16 = 0 
        property minor_version             : UInt16 = 0 
        property number_of_named_entries   : UInt16 = 0 
        property number_of_id_entries      : UInt16 = 0 


        # this is used for inheritance and child object storage. not technically a part of the win32 structure but logical to place it here as it makes inheritance easy 
        property children                  : Array(Image_Resource_Directory_Entry) = [] of Image_Resource_Directory_Entry
        
        # this is only used for exporting size and peformat but we need to store the padding to ensure we dont change the binary 
        property padding                   : Bytes = Bytes[] 
        property rsrc_offset               : UInt32 = 0 

        # parses a ImageResourceDirectory from a set of bytes. this should be exactly 16 bytes and only represents the core strucure without children or padding 
        def self.from_bytes(bts : Bytes ) : Image_Resource_Directory
            ret = Image_Resource_Directory.new()
            ret.characteristics          = IO::ByteFormat::LittleEndian.decode( UInt32 , bts[  0   ..  3   ]  ) 
            ret.time_date_stamp          = IO::ByteFormat::LittleEndian.decode( UInt32 , bts[  4   ..  7   ]  ) 
            ret.major_version            = IO::ByteFormat::LittleEndian.decode( UInt16 , bts[  8   ..  9   ]  ) 
            ret.minor_version            = IO::ByteFormat::LittleEndian.decode( UInt16 , bts[  10  ..  11  ]  ) 
            ret.number_of_named_entries  = IO::ByteFormat::LittleEndian.decode( UInt16 , bts[  12  ..  13  ]  ) 
            ret.number_of_id_entries     = IO::ByteFormat::LittleEndian.decode( UInt16 , bts[  14  ..  15  ]  ) 
            return ret  
        end 

        # parses and returns an Image_Resource_Directory stru8cture the represents the rsrc section 
        # offset is used for recursive and is not used for the parent call and is the byte offset from the start of the .rsrc directory
        def self.from_rsrc_section_bytes( section_bytes : Bytes , offset : UInt32|Int32 = 0 ) : Image_Resource_Directory
            # we initialize our node as the root node 
            root = Image_Resource_Directory.from_bytes(section_bytes[offset .. offset + 15])
            # puts "Parsing #{ to_c_fmnt_hex  root.to_slice}"
            entries_offset = offset + 16 # the start of our directory entries

            total_resources = root.number_of_named_entries + root.number_of_id_entries
            total_resources.times do |i| 
                # create our dir_entry object from the appropriate bytes for the parent node
                entry = Image_Resource_Directory_Entry.new(section_bytes[entries_offset + (i*8) .. entries_offset + (8*i) + 7])   
                # puts "Parsed dir entry: #{ to_c_fmnt_hex section_bytes[entries_offset + (i*8) .. entries_offset + (8*i) + 7]}"
                # now have the entry recursivly parse its children 
                entry.parse_children(section_bytes)

                # finally add our item to our entries array 
                root.children << entry 
            end 


            return root 
        end 

        def from_rsrc_section_bytes( section_bytes : Bytes , offset : Int32 = 0 ) : Image_Resource_Directory
            # we initialize our node as the root node 
            root = Image_Resource_Directory.from_bytes(section_bytes[offset .. offset + 15])

            entries_offset = offset + 16 # the start of our directory entries

            total_resources = root.number_of_named_entries + root.number_of_id_entries
            total_resources.times do |i| 
                # create our dir_entry object from the appropriate bytes for the parent node
                entry = Image_Resource_Directory_Entry.new(section_bytes[entries_offset + (i*8) .. entries_offset + (8*i) + 7])   
                
                # now have the entry recursivly parse its children 
                entry.parse_children(section_bytes)

                # finally add our item to our entries array 
                root.children << entry 
            end 


            return root 
        end 




        # exports the core strucutre to a slice 
        def to_slice() 
            io = IO::Memory.new() 

            # write our current to the io 
            IO::ByteFormat::LittleEndian.encode( characteristics           , io ) 
            IO::ByteFormat::LittleEndian.encode( time_date_stamp           , io ) 
            IO::ByteFormat::LittleEndian.encode( major_version             , io ) 
            IO::ByteFormat::LittleEndian.encode( minor_version             , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_named_entries   , io ) 
            IO::ByteFormat::LittleEndian.encode( number_of_id_entries      , io ) 

            return io.to_slice 
        end 

        # exports the treed structure of this and its children as it would apear in the pe file
        def to_pe_slice() 
            io = IO::Memory.new()
                        
            # set 4 ios to capture the appropriate bytes for each "data type" then we will write them all at once 
            dir_ent_queue = IO::Memory.new # Image_Resource_Directory and Image_Resource_Directory_Entry
            names_queue   = IO::Memory.new # Image_Resource_Directory_String # name strucure
            entry_queue   = IO::Memory.new # Image_Resource_Data_Entry # pointers to our data 
            data_queue    = IO::Memory.new # bytes of actual data 
            

            # write our own strucutre first before going into child strucures





            # we will use a double ended queue for keeping track of where we are and  to order the entries appropriately 
            q = Deque(
                        Image_Resource_Directory_Entry | # this is the "subfolder" of data
                        Image_Resource_Directory | # this is the table and subtables
                        Image_Resource_Data_Entry | # pointer/descriptor to the data 
                        Image_Resource_Directory_String # for our names that are referenced
                        ).new

            # puts "Adding the root to our strucure"
            # add ourself to the queue to start there 
            q.push self 

            # # # now itterate through the queue and add any children of the entry to the end of the queue while adding the appropriate data to its respective io 
            while q.size > 0
                # pull the first entry off the queue  
                c = q.shift 

                # add its data to the correct io
                if c.class == Image_Resource_Directory # the directory structure 

                    # puts "Adding a directory with with #{c.as(Image_Resource_Directory).children.size } children"
                    # write our object 
                    dir_ent_queue.write c.as(Image_Resource_Directory).to_slice() 
                    


                    # add children to the back of the queue if any 
                    c.as(Image_Resource_Directory).children.each do |cc| 
                        # puts "adding child of Image_Resource_Directory: #{cc.}"
                        # add the address offset for each child here not in the entry spot
                        # gets  
                        # write the directory's children addresses 
                        dir_ent_queue.write cc.to_slice
                        # cc.children.each do |ch| 
                        #     if ch.class == Image_Resource_Directory_String
                        #         names_queue.write ch.as(Image_Resource_Directory_String).to_slice
                        #     end 
                        # end 

                        q << cc # these will be of type Image_Resource_Directory_Entry
                    end 
                    # puts "Done adding dir children "
                elsif c.class ==  Image_Resource_Directory_Entry # id/pointer to a name/data/directory thing 
                    # puts "Its a dir entry... writing to the io..."
                    # puts "adding a directory entry"
                    # dir_ent_queue.write c.as(Image_Resource_Directory_Entry).to_slice 
                    # now add children to the queue if any 
                    c.as(Image_Resource_Directory_Entry).children.each do |child| 
                        if child.class == Image_Resource_Directory_String
                            names_queue.write child.as(Image_Resource_Directory_String).to_slice
                        end 
                        q << child unless child.class == Image_Resource_Directory_String
                    end 
                    # puts "Done adding dir entries children"
                elsif c.class == Image_Resource_Directory_String # its a name 
                    # puts "Writing String: #{ to_c_fmnt_hex  c.as(Image_Resource_Directory_String).to_slice }"
                    names_queue.write c.as(Image_Resource_Directory_String).to_slice 


                elsif c.class == Image_Resource_Data_Entry # pointer to actual data 
                    # puts "Data Entry: #{to_c_fmnt_hex  c.as(Image_Resource_Data_Entry).to_slice }"
                    entry_queue.write c.as(Image_Resource_Data_Entry).to_slice 
                    # puts "i would be enquing #{c.as(Image_Resource_Data_Entry).data } bytes to the data section"
                    data_queue.write c.as(Image_Resource_Data_Entry).data 
                else 
                    # puts c.class ===  Image_Resource_Directory_Entry

                    # raise "you shouldnt be able to put a class that isnt in the list to get here"
                end
            end 


            # write the io structures to the main io and then we can return...... lol 
            io.write ( dir_ent_queue .to_slice ) 
            io.write ( entry_queue   .to_slice ) 
            io.write ( names_queue   .to_slice ) 
            # io.write ( data_queue    .to_slice ) 

            #dont forget to write the padding
            io.write padding 

            return io.to_slice 

        end 







    end 



    # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
    # this strucutre is comprised of 2 dwords. the first being either a name or id depending on if the id is identified by an acutal string or by an id value. this causes the 1st bit to be a 1 in the case of a string and 0 if not
    class Image_Resource_Directory_Entry  
        
        # todo: maybe this would be a good idea to switch to a tuple or set of tuples? idk just a thought.....


        private property field1 : UInt32 = 0 
        private property field2 : UInt32 = 0 

        ## array of "pointers" of sorts to the next set of objects 
        property children : Array(Image_Resource_Directory|Image_Resource_Data_Entry|Image_Resource_Directory_String) = [] of (Image_Resource_Directory|Image_Resource_Data_Entry|Image_Resource_Directory_String)

        
        # feed in a 8 byte chunk as represent in the pefile 
        def initialize(bts : Bytes )
            @field1 = IO::ByteFormat::LittleEndian.decode(UInt32, bts[0 .. 3] )
            @field2 = IO::ByteFormat::LittleEndian.decode(UInt32, bts[4 .. 7] )
        end 


        # :nodoc: 
        # parses the children of this node given a full .rsrc byte section
        def parse_children( bts : Bytes ) 
            if string_ref? # we just add the string ref to our children the string is the end of a branch and cant have its own children 
                # our size of the string is the first word 
                # puts "Its a string ref | Name Offset: #{name_offset}|0x#{to_c_fmnt_hex name_offset}"
                size = IO::ByteFormat::LittleEndian.decode( UInt16,  bts[name_offset .. name_offset + 1 ])
                string = bts[name_offset + 2  .. name_offset + 2 + (size*2) - 1 ]
                s = Image_Resource_Directory_String.new( size, string )
                children << s 
            else 
                # nothing here its already encoded in the field1 property as the id 
            end 

            if is_directory?
                # puts "Here we would load a directory entry strucure "

                # parse our sub image res dir from our offsets 
                # d = Image_Resource_Directory.from_bytes(bts[name_offset .. name_offset + 15 ])
                # puts "Dir_Offset: #{ to_c_fmnt_hex directory_offset }"
                # puts ".rsrc size:  #{ to_c_fmnt_hex bts.size}"
                d = Image_Resource_Directory.from_rsrc_section_bytes( bts , directory_offset)
                
                # now populate its own children from the table but include the offset for the subdir 
                # d.from_rsrc_section_bytes()
                # # now i think we have to do addional parsing of d
                # # 
                # d.parse_

                # # finally add it to our children 
                children << d 

            elsif is_data? 
                # puts "Here we would parse it as a data object"
                # puts "Offset to data: #{ to_c_fmnt_hex  offset_to_data}"
                d = Image_Resource_Data_Entry.from_bytes( bts[offset_to_data  .. offset_to_data + 15 ] )
                # pp d.to_slice
                d.data =  bts[ offset_to_data .. offset_to_data + d.size - 1  ]
                children << d 
                
            else
                raise "you really broke something here didnt you"
            end 
        end 








        # # if the entry points to a string name its this one 
        # property name   : UInt32? = nil 

        # # else its identified by an ID 
        # property id     : UInt16? = nil 


        # property offset_to_data : UInt32 = 0 
        # property directory_offset : UInt32 = 0 


        # returns this as a slice 
        def to_slice() : Bytes 
            io = IO::Memory.new() 
            IO::ByteFormat::LittleEndian.encode(@field1, io ) 
            IO::ByteFormat::LittleEndian.encode(@field2, io ) 
            return io.to_slice 
        end 


        # returns true if the name is a string value 
        def string_ref? : Bool 
            return (( @field1 & 0x80000000 )  >> 31) == 1 
        end 


        def is_directory? : Bool 
            return (( @field2 & 0x80000000 )  >> 31) == 1 
        end 

        def is_data? 
            !is_directory?
        end 

        # returns the offset from the beginning of the .rsrc directory for the text value of the string 
        def name_offset : UInt32 
            return @field1 & 0x7FFFFFFF
        end 

        
        def directory_offset : UInt32 
            return @field2 & 0x7FFFFFFF
        end 



        # wraper for the field2 value 
        def offset_to_data : UInt32 
            return @field2 
        end 




        def id : UInt16 
            return @field1 ^ 0x80000000
        end 








    end 


    class Image_Resource_Directory_String

        # this is the size of the `name` string. it should be the size of the le-16 wide version of the string 
        property size : UInt16 = 0 

        # the actual string. it should be condensed from its le-16 format though
        property name : String = ""


        # takes the size of the string and the bytes of the string. size is probably the bytes.size/2 but meh its already precomputed 
        def initialize(@size : UInt16, bytes : Bytes)
            # now we have to convert from utf16-le 
            # yes this is absolutely aweful..... and should be fixed....but it works... 
            @name = String.from_utf16(
                bytes.unsafe_as(Slice(UInt16))
                ).split("")[0 .. (bytes.size / 2).to_i - 1 ].join
        end 

        def to_slice() 
            io = IO::Memory.new() 

            IO::ByteFormat::LittleEndian.encode(@size , io )
            
            # now encode the string to utf16.... kinda surprised crystal doesnt have a thing for this in the string class
            @name.to_utf16.each do |s| 
                IO::ByteFormat::LittleEndian.encode(s, io )
            end 
            
            return io.to_slice() 

        end 
    end 

    
    # the actual 
    class Image_Resource_Data_Entry
        property data_rva : UInt32 = 0 
        property size     : UInt32 = 0 
        property codepage : UInt32 = 0 
        property reserved : UInt32 = 0 

        # this is loaded by default when the .rsrc strucure is parsed
        property data      : Bytes = Bytes[] # set empty set of bytes by default. this noramlly is a pointer but its easy to parse and add this to this section for ease of use 


        # this returns the image_resource_data_entry item 16 byte styrucure WITHOUT the data since that technically goes elsewhere 
        def to_slice() : Bytes 
            io = IO::Memory.new 
            IO::ByteFormat::LittleEndian.encode(@data_rva , io  ) 
            IO::ByteFormat::LittleEndian.encode(@size     , io  ) 
            IO::ByteFormat::LittleEndian.encode(@codepage , io  ) 
            IO::ByteFormat::LittleEndian.encode(@reserved , io  ) 
            return io.to_slice 
        end 

        # feed in a 16 byte section and it will be parsed 
        def self.from_bytes(bts : Bytes ) : Image_Resource_Data_Entry
            ret = Image_Resource_Data_Entry.new
            ret.data_rva = IO::ByteFormat::LittleEndian.decode(UInt32, bts[0 .. 3 ])
            ret.size     = IO::ByteFormat::LittleEndian.decode(UInt32, bts[4 .. 7 ])
            ret.codepage = IO::ByteFormat::LittleEndian.decode(UInt32, bts[8 .. 11 ])
            ret.reserved = IO::ByteFormat::LittleEndian.decode(UInt32, bts[12 .. 15 ])

            return ret 
        end



    end 




end 