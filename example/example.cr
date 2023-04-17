require "../src/crystalpe"



pefile = CrystalPE::PE_File.new(ARGV[0])

pp pefile.dos_header
puts String.new(pefile.dos_header.e_magic )