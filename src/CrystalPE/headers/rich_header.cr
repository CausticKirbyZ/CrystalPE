
module CrystalPE
    class RichHeader
        # these are the actual fields present in the rich header structure. 
        # according to this https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/
        # its the dans header then 3 paddings of 8 bytes each then an array of RichHeaderEntry followed by the "Rich" header and the xor Key
        # looking at several binaries, it looks like there is an 8 byte null chunk at the end too but undocumented
        property dans_id                : Bytes? 
        property checksum_pad1          : Bytes? 
        property checksum_pad2          : Bytes? 
        property checksum_pad3          : Bytes? 
        property comp_ids               : Array(RichHeaderEntry) = [] of RichHeaderEntry
        property rich_id                : Bytes? 
        property xor_key                : Bytes? 

        property bytes                  : Bytes? 

        # Info stolen from here: https://github.com/kirschju/richheader/blob/master/prodids.py
        property lookup_table : Hash(Int32, String ) = {
            0x0000 => "prodidUnknown",
            0x0001 => "prodidImport0",
            0x0002 => "prodidLinker510",
            0x0003 => "prodidCvtomf510",
            0x0004 => "prodidLinker600",
            0x0005 => "prodidCvtomf600",
            0x0006 => "prodidCvtres500",
            0x0007 => "prodidUtc11_Basic",
            0x0008 => "prodidUtc11_C",
            0x0009 => "prodidUtc12_Basic",
            0x000a => "prodidUtc12_C",
            0x000b => "prodidUtc12_CPP",
            0x000c => "prodidAliasObj60",
            0x000d => "prodidVisualBasic60",
            0x000e => "prodidMasm613",
            0x000f => "prodidMasm710",
            0x0010 => "prodidLinker511",
            0x0011 => "prodidCvtomf511",
            0x0012 => "prodidMasm614",
            0x0013 => "prodidLinker512",
            0x0014 => "prodidCvtomf512",
            0x0015 => "prodidUtc12_C_Std",
            0x0016 => "prodidUtc12_CPP_Std",
            0x0017 => "prodidUtc12_C_Book",
            0x0018 => "prodidUtc12_CPP_Book",
            0x0019 => "prodidImplib700",
            0x001a => "prodidCvtomf700",
            0x001b => "prodidUtc13_Basic",
            0x001c => "prodidUtc13_C",
            0x001d => "prodidUtc13_CPP",
            0x001e => "prodidLinker610",
            0x001f => "prodidCvtomf610",
            0x0020 => "prodidLinker601",
            0x0021 => "prodidCvtomf601",
            0x0022 => "prodidUtc12_1_Basic",
            0x0023 => "prodidUtc12_1_C",
            0x0024 => "prodidUtc12_1_CPP",
            0x0025 => "prodidLinker620",
            0x0026 => "prodidCvtomf620",
            0x0027 => "prodidAliasObj70",
            0x0028 => "prodidLinker621",
            0x0029 => "prodidCvtomf621",
            0x002a => "prodidMasm615",
            0x002b => "prodidUtc13_LTCG_C",
            0x002c => "prodidUtc13_LTCG_CPP",
            0x002d => "prodidMasm620",
            0x002e => "prodidILAsm100",
            0x002f => "prodidUtc12_2_Basic",
            0x0030 => "prodidUtc12_2_C",
            0x0031 => "prodidUtc12_2_CPP",
            0x0032 => "prodidUtc12_2_C_Std",
            0x0033 => "prodidUtc12_2_CPP_Std",
            0x0034 => "prodidUtc12_2_C_Book",
            0x0035 => "prodidUtc12_2_CPP_Book",
            0x0036 => "prodidImplib622",
            0x0037 => "prodidCvtomf622",
            0x0038 => "prodidCvtres501",
            0x0039 => "prodidUtc13_C_Std",
            0x003a => "prodidUtc13_CPP_Std",
            0x003b => "prodidCvtpgd1300",
            0x003c => "prodidLinker622",
            0x003d => "prodidLinker700",
            0x003e => "prodidExport622",
            0x003f => "prodidExport700",
            0x0040 => "prodidMasm700",
            0x0041 => "prodidUtc13_POGO_I_C",
            0x0042 => "prodidUtc13_POGO_I_CPP",
            0x0043 => "prodidUtc13_POGO_O_C",
            0x0044 => "prodidUtc13_POGO_O_CPP",
            0x0045 => "prodidCvtres700",
            0x0046 => "prodidCvtres710p",
            0x0047 => "prodidLinker710p",
            0x0048 => "prodidCvtomf710p",
            0x0049 => "prodidExport710p",
            0x004a => "prodidImplib710p",
            0x004b => "prodidMasm710p",
            0x004c => "prodidUtc1310p_C",
            0x004d => "prodidUtc1310p_CPP",
            0x004e => "prodidUtc1310p_C_Std",
            0x004f => "prodidUtc1310p_CPP_Std",
            0x0050 => "prodidUtc1310p_LTCG_C",
            0x0051 => "prodidUtc1310p_LTCG_CPP",
            0x0052 => "prodidUtc1310p_POGO_I_C",
            0x0053 => "prodidUtc1310p_POGO_I_CPP",
            0x0054 => "prodidUtc1310p_POGO_O_C",
            0x0055 => "prodidUtc1310p_POGO_O_CPP",
            0x0056 => "prodidLinker624",
            0x0057 => "prodidCvtomf624",
            0x0058 => "prodidExport624",
            0x0059 => "prodidImplib624",
            0x005a => "prodidLinker710",
            0x005b => "prodidCvtomf710",
            0x005c => "prodidExport710",
            0x005d => "prodidImplib710",
            0x005e => "prodidCvtres710",
            0x005f => "prodidUtc1310_C",
            0x0060 => "prodidUtc1310_CPP",
            0x0061 => "prodidUtc1310_C_Std",
            0x0062 => "prodidUtc1310_CPP_Std",
            0x0063 => "prodidUtc1310_LTCG_C",
            0x0064 => "prodidUtc1310_LTCG_CPP",
            0x0065 => "prodidUtc1310_POGO_I_C",
            0x0066 => "prodidUtc1310_POGO_I_CPP",
            0x0067 => "prodidUtc1310_POGO_O_C",
            0x0068 => "prodidUtc1310_POGO_O_CPP",
            0x0069 => "prodidAliasObj710",
            0x006a => "prodidAliasObj710p",
            0x006b => "prodidCvtpgd1310",
            0x006c => "prodidCvtpgd1310p",
            0x006d => "prodidUtc1400_C",
            0x006e => "prodidUtc1400_CPP",
            0x006f => "prodidUtc1400_C_Std",
            0x0070 => "prodidUtc1400_CPP_Std",
            0x0071 => "prodidUtc1400_LTCG_C",
            0x0072 => "prodidUtc1400_LTCG_CPP",
            0x0073 => "prodidUtc1400_POGO_I_C",
            0x0074 => "prodidUtc1400_POGO_I_CPP",
            0x0075 => "prodidUtc1400_POGO_O_C",
            0x0076 => "prodidUtc1400_POGO_O_CPP",
            0x0077 => "prodidCvtpgd1400",
            0x0078 => "prodidLinker800",
            0x0079 => "prodidCvtomf800",
            0x007a => "prodidExport800",
            0x007b => "prodidImplib800",
            0x007c => "prodidCvtres800",
            0x007d => "prodidMasm800",
            0x007e => "prodidAliasObj800",
            0x007f => "prodidPhoenixPrerelease",
            0x0080 => "prodidUtc1400_CVTCIL_C",
            0x0081 => "prodidUtc1400_CVTCIL_CPP",
            0x0082 => "prodidUtc1400_LTCG_MSIL",
            0x0083 => "prodidUtc1500_C",
            0x0084 => "prodidUtc1500_CPP",
            0x0085 => "prodidUtc1500_C_Std",
            0x0086 => "prodidUtc1500_CPP_Std",
            0x0087 => "prodidUtc1500_CVTCIL_C",
            0x0088 => "prodidUtc1500_CVTCIL_CPP",
            0x0089 => "prodidUtc1500_LTCG_C",
            0x008a => "prodidUtc1500_LTCG_CPP",
            0x008b => "prodidUtc1500_LTCG_MSIL",
            0x008c => "prodidUtc1500_POGO_I_C",
            0x008d => "prodidUtc1500_POGO_I_CPP",
            0x008e => "prodidUtc1500_POGO_O_C",
            0x008f => "prodidUtc1500_POGO_O_CPP",
            0x0090 => "prodidCvtpgd1500",
            0x0091 => "prodidLinker900",
            0x0092 => "prodidExport900",
            0x0093 => "prodidImplib900",
            0x0094 => "prodidCvtres900",
            0x0095 => "prodidMasm900",
            0x0096 => "prodidAliasObj900",
            0x0097 => "prodidResource",
            0x0098 => "prodidAliasObj1000",
            0x0099 => "prodidCvtpgd1600",
            0x009a => "prodidCvtres1000",
            0x009b => "prodidExport1000",
            0x009c => "prodidImplib1000",
            0x009d => "prodidLinker1000",
            0x009e => "prodidMasm1000",
            0x009f => "prodidPhx1600_C",
            0x00a0 => "prodidPhx1600_CPP",
            0x00a1 => "prodidPhx1600_CVTCIL_C",
            0x00a2 => "prodidPhx1600_CVTCIL_CPP",
            0x00a3 => "prodidPhx1600_LTCG_C",
            0x00a4 => "prodidPhx1600_LTCG_CPP",
            0x00a5 => "prodidPhx1600_LTCG_MSIL",
            0x00a6 => "prodidPhx1600_POGO_I_C",
            0x00a7 => "prodidPhx1600_POGO_I_CPP",
            0x00a8 => "prodidPhx1600_POGO_O_C",
            0x00a9 => "prodidPhx1600_POGO_O_CPP",
            0x00aa => "prodidUtc1600_C",
            0x00ab => "prodidUtc1600_CPP",
            0x00ac => "prodidUtc1600_CVTCIL_C",
            0x00ad => "prodidUtc1600_CVTCIL_CPP",
            0x00ae => "prodidUtc1600_LTCG_C",
            0x00af => "prodidUtc1600_LTCG_CPP",
            0x00b0 => "prodidUtc1600_LTCG_MSIL",
            0x00b1 => "prodidUtc1600_POGO_I_C",
            0x00b2 => "prodidUtc1600_POGO_I_CPP",
            0x00b3 => "prodidUtc1600_POGO_O_C",
            0x00b4 => "prodidUtc1600_POGO_O_CPP",
            0x00b5 => "prodidAliasObj1010",
            0x00b6 => "prodidCvtpgd1610",
            0x00b7 => "prodidCvtres1010",
            0x00b8 => "prodidExport1010",
            0x00b9 => "prodidImplib1010",
            0x00ba => "prodidLinker1010",
            0x00bb => "prodidMasm1010",
            0x00bc => "prodidUtc1610_C",
            0x00bd => "prodidUtc1610_CPP",
            0x00be => "prodidUtc1610_CVTCIL_C",
            0x00bf => "prodidUtc1610_CVTCIL_CPP",
            0x00c0 => "prodidUtc1610_LTCG_C",
            0x00c1 => "prodidUtc1610_LTCG_CPP",
            0x00c2 => "prodidUtc1610_LTCG_MSIL",
            0x00c3 => "prodidUtc1610_POGO_I_C",
            0x00c4 => "prodidUtc1610_POGO_I_CPP",
            0x00c5 => "prodidUtc1610_POGO_O_C",
            0x00c6 => "prodidUtc1610_POGO_O_CPP",
            0x00c7 => "prodidAliasObj1100",
            0x00c8 => "prodidCvtpgd1700",
            0x00c9 => "prodidCvtres1100",
            0x00ca => "prodidExport1100",
            0x00cb => "prodidImplib1100",
            0x00cc => "prodidLinker1100",
            0x00cd => "prodidMasm1100",
            0x00ce => "prodidUtc1700_C",
            0x00cf => "prodidUtc1700_CPP",
            0x00d0 => "prodidUtc1700_CVTCIL_C",
            0x00d1 => "prodidUtc1700_CVTCIL_CPP",
            0x00d2 => "prodidUtc1700_LTCG_C",
            0x00d3 => "prodidUtc1700_LTCG_CPP",
            0x00d4 => "prodidUtc1700_LTCG_MSIL",
            0x00d5 => "prodidUtc1700_POGO_I_C",
            0x00d6 => "prodidUtc1700_POGO_I_CPP",
            0x00d7 => "prodidUtc1700_POGO_O_C",
            0x00d8 => "prodidUtc1700_POGO_O_CPP",
            0x00d9 => "prodidAliasObj1200",
            0x00da => "prodidCvtpgd1800",
            0x00db => "prodidCvtres1200",
            0x00dc => "prodidExport1200",
            0x00dd => "prodidImplib1200",
            0x00de => "prodidLinker1200",
            0x00df => "prodidMasm1200",
            0x00e0 => "prodidUtc1800_C",
            0x00e1 => "prodidUtc1800_CPP",
            0x00e2 => "prodidUtc1800_CVTCIL_C",
            0x00d3 => "prodidUtc1800_CVTCIL_CPP",
            0x00e4 => "prodidUtc1800_LTCG_C",
            0x00e5 => "prodidUtc1800_LTCG_CPP",
            0x00e6 => "prodidUtc1800_LTCG_MSIL",
            0x00e7 => "prodidUtc1800_POGO_I_C",
            0x00e8 => "prodidUtc1800_POGO_I_CPP",
            0x00e9 => "prodidUtc1800_POGO_O_C",
            0x00ea => "prodidUtc1800_POGO_O_CPP",
            0x00eb => "prodidAliasObj1210",
            0x00ec => "prodidCvtpgd1810",
            0x00ed => "prodidCvtres1210",
            0x00ee => "prodidExport1210",
            0x00ef => "prodidImplib1210",
            0x00f0 => "prodidLinker1210",
            0x00f1 => "prodidMasm1210",
            0x00f2 => "prodidUtc1810_C",
            0x00f3 => "prodidUtc1810_CPP",
            0x00f4 => "prodidUtc1810_CVTCIL_C",
            0x00f5 => "prodidUtc1810_CVTCIL_CPP",
            0x00f6 => "prodidUtc1810_LTCG_C",
            0x00f7 => "prodidUtc1810_LTCG_CPP",
            0x00f8 => "prodidUtc1810_LTCG_MSIL",
            0x00f9 => "prodidUtc1810_POGO_I_C",
            0x00fa => "prodidUtc1810_POGO_I_CPP",
            0x00fb => "prodidUtc1810_POGO_O_C",
            0x00fc => "prodidUtc1810_POGO_O_CPP",
            0x00fd => "prodidAliasObj1400",
            0x00fe => "prodidCvtpgd1900",
            0x00ff => "prodidCvtres1400",
            0x0100 => "prodidExport1400",
            0x0101 => "prodidImplib1400",
            0x0102 => "prodidLinker1400",
            0x0103 => "prodidMasm1400",
            0x0104 => "prodidUtc1900_C",
            0x0105 => "prodidUtc1900_CPP",
            0x0106 => "prodidUtc1900_CVTCIL_C",
            0x0107 => "prodidUtc1900_CVTCIL_CPP",
            0x0108 => "prodidUtc1900_LTCG_C",
            0x0109 => "prodidUtc1900_LTCG_CPP",
            0x010a => "prodidUtc1900_LTCG_MSIL",
            0x010b => "prodidUtc1900_POGO_I_C",
            0x010c => "prodidUtc1900_POGO_I_CPP",
            0x010d => "prodidUtc1900_POGO_O_C",
            0x010e => "prodidUtc1900_POGO_O_CPP"
        }

        # takes in the raw values 
        def self.xor_decrypt(value : Bytes , key : Bytes ) : Bytes
            return value.map_with_index { |vv, i| vv = vv ^ key[i] }
        end 

        # returns the contents of the rich header in a le formatted byte array 
        def raw_bytes() : Bytes 
            if @bytes.nil? 
                return Bytes[] # return empty set of bytes if its nil 
            end 
            return @bytes.not_nil!
        end
    end

    class RichHeaderEntry
        property build_id  : Bytes? # 32 bit 
        property prod_id   : Bytes? # 16 bit 
        property buld_id   : Bytes? # 16 bit 
    end
end 