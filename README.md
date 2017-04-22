# Overview
This is a complete guide to getting our PFA testing environment up and running. This guide assumes a number of environment variables:

* $TOP - a folder containing all downloaded repositories. e.g., $TOP/linux-4.6.2 should point to your linux source directory.
* $RISCV - a folder containing the local install of the RISC-V toolchain (I don't recommend installing them to your root directory, just in case). See riscv-tools instructions for how this gets setup.

# riscv-tools
We'll need to install the riscv toolchain in order to cross-compile for linux. Get the source from [here](https://github.com/riscv/riscv-tools). For our qemu to work, we'll need to checkout an older commit:

        $ git checkout ad9ebb8557e32241bfca047f2bc628a2bc1c18cb

There are a lot of instructions in the README, many of them are wrong. Instead, I've replicated the relevant instructions here:

        $ git submodule update --init --recursive
        $ export RISCV=/path/to/install/riscv/toolchain
        $ ./build.sh

Enter the `riscv-gnu-toolchain` directory and run the configure script
to generate the Makefile.

        $ ./configure --prefix=$RISCV
        $ make linux

Note: The default for the build.sh script is to install riscv64-unknown-elf-gcc which doesn't work for building the kernel (and maybe other stuff?). Anyway, you need to always use the riscv64-unknown-linux-gnu- prefix instead (which is built with the "make linux" command).

# riscv-qemu
For this project, we are using a modified qemu from [here](https://github.com/WabashOS/riscv-qemu-pk). The instructions on that page mostly seem to work, although you may need to disable werror when configuring (add --disable-werror to the ./configure command line).

# busybox
We use busybox as our linux userspace. It basically wraps up all the necessary components into a nice, single binary. Get it [here](http://www.busybox.net). We're using busybox 1.23.1, but the version probably isn't very important.

First, obtain and untar the source:

	$ curl -L https://busybox.net/downloads/busybox-1.23.1.tar.bz2 | tar -xj

I'm currently using the "defconfig":

	$ cd busybox-1.23.1
	$ make defconfig

We will need to change the cross-compiler, set the build to
"static" (if desired, you can make it dynamic, but you'll have to copy some
libraries later). Here are the recommended config changes (make menuconfig):

* "compile static" under general->build options
* set cross-compiler prefix (under general->build options) to "riscv64-unknown-linux-gnu-"
* remove inetd from networking tools (if you run into compiler errors like I did)
* Disable job control for `ash` under the `ash` applet.

Once you've finished, make BusyBox. You don't need to specify
`$ARCH`, because we've passed the name of the cross-compiler prefix.

	$ make

# Linux
This repo contains just the risc-v specific parts of the linux kernel and is intended to be overlayed on top of the orginal sources. Note the PFA branch checks out the right commit to play nice with risc-v qemu and risc-v tools. various commits break various things so it's good to be careful here.

## Obtaining kernel sources

Overlay the `riscv` architecture-specific subtree onto an upstream release:

        $ curl -L https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.6.2.tar.xz | tar -xJ
        $ cd linux-4.6.2
        $ git init
        $ git remote add -t pfa origin git@github.com:WabashOS/riscv-linux.git
        $ git fetch
        $ git checkout -f -t origin/pfa

Note that the `-t <branch>` option minimizes the history fetched.
To add another branch:

        $ git remote set-branches --add origin <branch>
        $ git fetch

## Compiling

1. Create kernel configuration based on architecture defaults:

        $ make ARCH=riscv defconfig

1. Optionally edit the configuration via an ncurses interface:

        $ make ARCH=riscv menuconfig

1. PFA-specific config (via make ARCH=riscv menuconfig)
  
    * sysfs in "filesystems->pseudo filesystems" (CONFIG_SYSFS)
    * "Initial RAM Filesystem" in "general->" (CONFIG_BLK_DEV_INITRD)
    * "Initial RAM Filesystem Path" = "arch/riscv/initramfs.txt" in "general->" (CONFIG_INITRAMFS_SOURCE)
    * frontswap in "kernel->" (CONFIG_FRONTSWAP)

1. initramfs
Note that the comitted arch/riscv/initramfs.txt is tuned for my system, be sure to edit it to point to your install of busybox.

1. Build the uncompressed kernel image:

        $ make ARCH=riscv vmlinux

# BBL
The berkeley boot loader ties everything together and creates a bootable image that qemu can run. Configure and build it thusly:

        $ cd $TOP/riscv-tools/riscv-pk
        $ ./configure --prefix=RISCV --with-payload=$TOP/linux-4.6.2/vmlinux --host=riscv64-unknown-linux-gnu
        $ cd build/
        $ make bbl

# Tying it all together
The final image can now be run under qemu:

        $ qemu-system-riscv64 -kernel $TOP/riscv-tools/riscv-pk/build/bbl -nographic
        
To rebuild, you have to repeat all the steps, starting from the oldest thing you changed:
1. build busybox
1. build linux
1. build bbl

This means that if you change linux, you need to recompile it, then recompile bbl before you see the full changes. I should probably write a script for this or something...
