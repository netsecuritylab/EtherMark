This repository contains the data and code for the **EtherMark** paper accepted and published at WoWMoM 2026.
> **Note:** ALL THE COMMANDS BELOW WHERE TESTED ONLY ON **KUBUNTU 25.04 LTS**

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

# Simple EtherMark Architecture Deployment
<img width="499" height="135" alt="arch2" src="https://github.com/user-attachments/assets/d9d0bfcb-7c9b-4a0f-bd29-c42074f8c6ac" />


Requirements:
- Access point
- Linux Workstation

**Wire the `Access Point`, `Workstation` and `Gateway` as in the picture above.**

Setup the `Workstation` as a bridge between the `Access Point` and the `Gateway`.\
(Replace `eth0` and `eth1` with your interface names).
```bash
ip l add name br0 type bridge
ip l set eth0 master br0
ip l set eth1 master br0
ip l set br0 up
```
Setup the ENAD functionality on the `Workstation`.\
(Replace `eth0` with your interface name and `gw0_MAC` with the MAC address of your `gw0` interface).

```bash
ebtables -t nat -A PREROUTING -i eth0 --dst F2:FF:00:00:00:00/ff:ff:00:00:00:00 -j dnat --to-destination <gw0_MAC>
```
To capture labelled packets just use `tcpdump`.
```bash
tcpdump -i eth0 -w labelled_dataset.pcap
```

# Scripts
The `Script` folder contains a Python3 script that can perform label expansion.

```bash
main.py <cmd>
```
- `lexpand` to perform label expasion (for fast label expansion use the --in-place flag).
- `split` to split a given PCAP into one PCAP per label.

# Dataset

The dataset can be found [here](https://osf.io/9bzwt/overview?view_only=ee4e276497144ad0b1b4176039042f91). It is split over two zip files.
