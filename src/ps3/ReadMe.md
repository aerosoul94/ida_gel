# ps3ldr
An IDA Pro loader for PS3 Cell Lv-2 OS.

## Features
* Loads symbols
* Processes and labels exports and imports
* PRX relocation
* Find and set TOC address
* Supports prototype executables

## Usage
### NID Database
This loader expects an NID xml database named `ps3.xml` to be present within IDA's loaders directory. For convenience, it is the same xml database format that was used in xorloser's loader.

Example:

    <?xml version="1.0"?>
    <IdaInfoDatabase>
        <Group name="moduleName">
            <Entry id="0x1529E506" name="cellAdecDecodeAu"/>
        </Group>
    </IdaInfoDatabase>

### PRX Relocation
Relocation of PRX's is possible by checking the *Manual Load* checkbox in IDA's *Load New File* dialog, then before loading the loader will ask for a relocation base address.