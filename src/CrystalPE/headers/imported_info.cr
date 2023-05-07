
module CrystalPE 
    # this class is not part of windows but a medium for ease of use while using import adress table items
    class ImportedInfo 
        property image_import_descriptor            : ImageImportDescriptor = ImageImportDescriptor.new()
        property functions                          : Array(ImageImportByName| ImageImportByOrdinal) = [] of (ImageImportByName  | ImageImportByOrdinal      )
        property dll_name                           : String = ""
        # property bound                              : Bool = false # default value here 

    end 
end  