
module CrystalPE 
    # this class is not part of windows but a medium for ease of use while using import adress table items
    class ImportedInfo 
        property image_import_descriptor            : ImageImportDescriptor = ImageImportDescriptor.new()
        property functions                          : Array(ImageImportByName) = [] of ImageImportByName        
        property dll_name                           : String = ""
    end 
end 