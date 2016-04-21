# 3ds-to-cia
Just another 3DS to CIA converter for Linux and Windows.

## Usage
### Easy (precompiled version)
Just unzip the released version, put your roms in the `roms` directory, put the xorpads in the `xorpads` directory and launch 3ds-to-cia.  
The script will tell you what you need to do.  
The resulting CIAs will be found in `cia` directory.

### Pro (from sources)
Install `python2` with `colorama`, build [make_cia](https://github.com/ihaveamac/ctr_toolkit) and put it in your PATH, then just launch `./3ds-to-cia.py`

## Building release
You need to install python2 with pyinstaller and colorama, then:
```
pyinstaller 3ds-to-cia.spec
```

in `distro` directory you will find the resulting binary.

Put the binary in a folder with `cia`, `roms` and `xorpads` empty directories, zip it and redistribuite.

## Credits
* `mid-kid` for the informations about the procedure
* `3DSGuy` for make_cia
* `ncchinfo.bin` generation based on `ArchShift` and `d0k3` [Decrypt9WIP's ncchinfo_gen_exh.py](https://github.com/d0k3/Decrypt9WIP/blob/master/scripts/ncchinfo_gen_exh.py)
