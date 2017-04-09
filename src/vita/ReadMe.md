# vitaldr
An IDA Pro loader for Playstation Vita OS.

## Features
* Loads symbols
* Supports kernel and user modules.
* Processes and labels exports and imports

## Usage
### NID Database
This loader expects an NID database named `vita.txt` to be present within IDA's loader directory. The format is simple:

    0x34EFD876 sceIoWrite
    0xC70B8886 sceIoClose

## Todo
* Although it does process all relocation formats (form 0 - 9), module relocation still needs to be completed.