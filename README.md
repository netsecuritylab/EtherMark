This repository contains the data and code for the **EtherMark** paper accepted and published at WoWMoM 2026.
> **Note:** ALL THE COMMANDS BELOW WHERE TESTED ONLY ON **UBUNTU 24.04 LTS**

# Building EtherMark

To build EtherMark, obtain the GKI kernel source for your target device.
See [building kernels](https://source.android.com/docs/setup/build/building-kernels) documentation.
> **Note:** Kernel 6.1 is the minimum required version.

For devices with Kernel 6.1:
```bash
mkdir android-kernel && cd android-kernel
repo init -u https://android.googlesource.com/kernel/manifest -b common-android14-6.1
repo sync
```

After having obtained the kernel sources copy the `oot` folder into the android kernel folder.


To build the module use the following command.
```bash
tools/bazel build oot/modules/EtherMark:EtherMark
```

Once the module has been built copy the `.ko` file on the device then use `insmod` to load it.

# Scripts
The `Script` folder contains a Python3 script that can perform label expansion.

```bash
main.py <cmd>
```
- `lexpand` to perform label expasion (for fast label expansion use the --in-place flag).
- `split` to split a given PCAP into one PCAP per label.

# Dataset

The dataset can be found [here](https://osf.io/9bzwt/overview?view_only=ee4e276497144ad0b1b4176039042f91). It is split over two zip files.
