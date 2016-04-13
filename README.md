# 3ds-to-cia
Just another 3DS to CIA converter for Linux and Windows (64bit)

## Usage
Just unzip the released version, put your roms in the `roms` directory, put the xorpads in the `xorpads` directory and launch 3ds-to-cia

The script will tell you what you need to do.
The resulting CIAs will be found in `cia` directory

## Requirements
If you are not using precompiled (pyinstaller) binaries, you need to find or compile `rom_tool` and `makerom` under Linux or `rom_tool.exe` and `makerom.exe` under Windows.  
You need to put the downloaded files in the correct directory `tools/linux64` or `tools/win64`.

You also need to create the correct directories: `cia`, `roms`, `xorpads`.

## Building release

You need to install python2 with pyinstaller and colorama, then:

```
pyinstaller -F 3ds-to-cia.spec
```

in `distro` directory you will find the resulting binary.

Put the binary in a folder with `cia`, `roms` and `xorpads` empty directories, zip it and redistribuite.
