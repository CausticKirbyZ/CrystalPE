module CrystalPE 
    # this represents a security strucutre in the binary. usually this is an x509 cert 
    class Security
        property length     : UInt32  = 0 # DWORD
        property revision   : UInt16  = 0 # WORD
        property type       : UInt16  = 0 # WORD
        property bytes      : Bytes   = Bytes[]



    end 
end 