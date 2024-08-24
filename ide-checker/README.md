# ide_checker is a tool to check the PCIE IDE TLP or CXL IDE FLIT.

## Standard

### PCI-SIG
PCIe Base Specification Version [6.2](https://members.pcisig.com/wg/PCI-SIG/document/20590), section 6.33 IDE

### CXL
Compute Express Link Specification Revision [3.1](https://computeexpresslink.org/cxl-specification), section 11.3 CXL.cachemem IDE

## Steps

### Windows build

```
cd ide-checker
mkdir build
cd build
cmake -G"NMake Makefiles" -DARCH=x64 -DTOOLCHAIN=VS2019 -DTARGET=Debug -DCRYPTO=mbedtls ..
nmake
```

The final image is at `bin\ide_checker.exe`.
