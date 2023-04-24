require "bindata"


class PE < BinData 
    endian :little 
    
    string :magic_bytes, default: "MA", length: 2 
   
    uint16 :e_cblp     
    uint16 :e_cp       
    uint16 :e_crlc     
    uint16 :e_cparhdr  
    uint16 :e_minalloc 
    uint16 :e_maxalloc 
    uint16 :e_ss       
    uint16 :e_sp       
    uint16 :e_csum     
    uint16 :e_ip       
    uint16 :e_cs       
    uint16 :e_lfarlc   
    uint16 :e_ovno     
    uint16 :e_res      
    uint16 :e_oemid    
    uint16 :e_oeminfo  
    uint16 :e_res2,     
    uint32 :e_lfanew   
end