# CrystalPE

CrystalPE is a windows [PE](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) parsing library for Crystal. This shard is designed with the goal of malware analysis/research and threat hunting capabilities. The lilbrary supports both x86/64 pe files. 

Several executables are included in the "demope" folder. These were used for testing and can be built or downloaded for additional tests. 

## Installation
As with all crystal shards:
1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     crystalpe:
       github: CausticKirbyZ/CrystalPE
   ```
2. Run `shards install`


## Usage
Example of itterating through the strings in a pe file to identify a potential compiler used: 
```crystal
require "crystalpe"

pefile = CrystalPE::PEFile.new( "HelloWorld.exe" )
pefile.strings().each do |str| 
    if str.includes? "GCC"
        puts "This file was likely compiled with GCC" 
    end 
end 
```



## Supports: 
### Parsing: 
- Basic PE Parsing.
  - Dos Headers
  - Dos Stub 
  - Rich headers
  - nt/pe headers 
  - nt/pe optional headers 
  - data directories 
  - import table 
  - export table 
  - overlay(as a blob)

### Info: 
- basic hashing functions ( md5, sha1, sha256, sha512 )
- shannon entropy calculation 


### Modifying 
- PE Checksum fixing/modification. 
- Modification of headers. 
- writing files  back to disk without breaking execution. 
- Updating DOS Stubs. 
- inserting Rich header stubs (be careful with .net executables)


## Some Support 
- .NET headers: basic parsing support but needs to be expanded and clarified. 
- section headers: these are parsed out as Byte chunks and need to be turned into classes to be easier to work with. 

## ToDo: 
Add parsing/classes for: 
- Debug table 
- reloacations 
- security table 
- resource table 
- Add more .net calculations 

Add validation functions for checksums and offsets.

update the project to be more inline with crystal code guidelines.... yes im bad at things 

document more things.


## Feature Requests/Bugs 
If you have feature requests / bugs submit an issue or (even better) a pull request. 

if its a bug, please specify what it is, how you found it, and how it can be fixed(if you know).

For feature requests please describe in detail, the feature you want and the reason it should be in the core library. 



## Development

TODO: Write development instructions here









## Contributing

1. Fork it ([https://github.com/your-github-user/crystalpe/fork](https://github.com/your-github-user/crystalpe/fork))
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [CausticKirbyZ](https://github.com/CausticKirbyZ) - creator and maintainer


## References: 
- While this project is not a direct port, the go [pe](https://github.com/saferwall/pe) package was refernced several times as i was writing this. 
- Microsofts [PE File](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) format docs. 
- [NTCore](https://ntcore.com) has a TON of documentation and breakdowns for various formats and pe structures. 
- 