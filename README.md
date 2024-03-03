<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# xdpsnoop: A tool to trace XDP installation on NIC drivers

`xdpsnoop` is an eBPF-based tool to trace XDP program installation and removal on NIC drivers. It is useful when something bad happens to the XDP program installation, and some error message will be printed if provided.

## Prerequisites

Linux kernel version 5.2 or later with:

- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_KPROBES=y`
- `CONFIG_FUNCTION_TRACER=y`

## Usage

```sh
sudo ./xdpsnoop
2024/03/03 15:00:33 Listening for events...
2024/03/03 15:00:36 Installed XDP to ifindex=2 ifname=ens33 bpf_prog_id=438 bpf_prog_name=dummy
2024/03/03 15:00:37 Removed XDP from ifindex=2 ifname=ens33
```

## Build

With Go and clang installed, you can build `xdpsnoop` by running:

```sh
git clone https://github.com/Asphaltt/xdpsnoop.git
cd xdpsnoop
go generate
go build
```

## Credits

Thanks for [pwru](github.com/cilium/pwru) to retrieve BTF info from all kernel modules.

## License

`xdpsnoop` is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

Its bpf source code is licensed under the GNU General Public License v2.0. See [LICENSE.GPL-2.0](./bpf/LICENSE.GPL-2.0) for the full license text.
