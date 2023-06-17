ECM-like encoding to model non-data in bin/cue image files

Like ECM but different in a few ways:

* Models more of the non-data parts of a bin file for typically more filesize reduction
* Faster
* The non-data encoding is separate from the data, which is better for further processing particularly with precomp
* Encode is "streamable" but requires enough RAM to fit entire input in memory
* Pipe with - as filename
* Suitable for random access

## Silesia test

silesia.zip is a test file used by precomp to showcase how it can losslessly decode weak compression to then compress with stronger compression. silesia.bin is a raw mode 1 bin image containing silesia.zip as the only file in its filesystem, used for this test:

```
                .bin     .ecm     .ybe
input           78084048 68091165 67991561
input + xz -6   77374740 67524752 67426612
input + precomp 77374819 67524943 47383783
```

ecm and ybe losslessly remove the ECC, xz cannot compress the incompressible, ybe allows precomp 

## ybe help

ybe v0.2

Encode:
 ybe src.bin
 ybe src.bin dest.ybe
 ybe e src.bin dest.ybe

Decode:
 unybe src.ybe
 unybe src.ybe dest.bin
 ybe d src.ybe dest.bin

Test:
 ybe t src.bin

- can take the place of src/dest to pipe with stdin/stdout

## ybe_mount

ybe_mount is a FUSE implementation that allows ybe files to be mounted to an empty directory. Once mounted the directory contains a virtual bin file (the original image), and if possible a virtual iso file (the cooked version of the image containing only the data fields of each sector). These virtual files are read only and random access like a normal file, they can be used for example by mounting the images filesystem with your favourite tool or loaded with an emulator, neither of which need to support ybe format directly.

A user could go one step further by storing ybe files on a filesystem with transparent compression/dedupe (like BTRFS/ZFS), meaning they can directly use a compressed file without having to manually decompress.
