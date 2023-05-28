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

