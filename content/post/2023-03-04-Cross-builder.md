---
title: "Cross build and packaging"
subtitle: "It compiles! Ship it!"
date: 2023-03-04T03:27:12+03:00
tags: ["openSUSE","SLES","SUSE", "Linux", "opens source", "zypper", "OBS", "developer tools"]
type: post
---

## Introduction

Let's start by clarifying what we mean by cross-building and cross-packaging. Cross-compilation is the process of compiling source code on one platform, called the host, in order to generate an executable binary for a different target platform. The emphasis here is on the word "different". The target platform may have a different CPU architecture, such as when we work on an x86 computer and want to build software for a Raspberry Pi board with an ARM CPU. But even if the target platform has the same CPU architecture as the host, there may be several other possible differences. For example, the host may be running [Debian Sid](https://wiki.debian.org/DebianUnstable), while the target may be running [openSUSE Leap](https://www.opensuse.org/#Leap). Different Linux distributions may have different compilers, linkers, and run-time libraries. Even when using the same distribution as the host for the target, they may be different releases, such as openSUSE Tumbleweed and Leap. In short, nothing guarantees that the target system will have the same shared libraries as the host system.


Therefore, compiling, building, and packaging against the libraries and with the toolchain of the host system may not result in very portable or usable binaries and packages. This is exactly why we need cross builders and cross packaging tools.


In the SUSE ecosystem, the Open Build Service provides cross-build and cross-packaging services for most users in most cases. Most users do not need to bother about the details. We just push the code to OBS, and it will take care of the dirty details for us. Awesome. However, sometimes, we may feel the need to do things locally. Although the cloud is there to serve us, sometimes, we just want to keep the compilation and packaging process in our hands and observe failures and successful builds closely. Or we just want to understand what exactly is going on during a package build process and what tools are being used. It is extremely satisfying to look under the hood.


This weird obsession of seeing the running engine and keeping the processes close to us motivated me to create a cross-builder environment and tool. An additional motivating factor was that I am a maintainer of a few packages in openSUSE and SLES distributions, and very often, I need to release the same update for SLES12, SLES15, and openSUSE Tumbleweed, knowing that the same code actually builds and works across all releases.


Here, I must note a very important disclaimer. I am well aware that I am not the first coder with such needs. I do know that there are many capable solutions and tools for this job. The reason I decided to create my own was that I wanted a distribution-agnostic solution with minimal footprint and full permeability, transparency. I know that it is possible to make and use a container-based solution for this problem. We have [done it](https://launchpad.net/~ubuntu-sdk-team/+archive/ubuntu/tools-development) with [Timo](https://github.com/tjyrinki), [Benjamin](https://github.com/bzeller) and [Cris](https://kalikiana.gitlab.io/) back in 2017. But this time, I wanted to try out something old-school, simple, and low-cost. I wanted a builder that is walking through the whole process exactly how a human would do manually but fully automatic.


### The Chroot
When it comes to file system isolation and confinement, nothing beats the good old chroot. The chroot was first released in 1979 for Version 7 Unix. Since then, chroot has been available on all Linux distributions, and many build systems have been developed around it. For example, [Mock](https://rpm-software-management.github.io/mock/) on Fedora and RHEL  or the very [OBS build script](https://github.com/openSUSE/obs-build/blob/master/build). On Debian and Ubuntu, [sbuild](https://packages.debian.org/search?keywords=sbuild) is the way to go, or the naked debootstrap that works with chrootable rootfs.


The difference in how I approached the problem compared to existing solutions is that I wanted to control the content of the chroot. I wanted to see how small a rootfs could get while still providing nothing else but a `bash` and a fully functioning `zypper`. I checked all the dependencies of each package and their binaries with ldd to see what shared libraries they need. For a couple of hours, I was the heaviest user of the `zypper se --provides --match-exact [library]`command to see what package provides the library or whatever resource a functioning bash and zypper needs.


The one liner what helped me to find out what are the effective dependencies of zypper was this:
```
$ ldd /usr/bin/zypper|awk '{print $1}'|sort|uniq|xargs whereis|awk '{print $NF}'| \
xargs  zypper --non-interactive --no-gpg-checks --gpg-auto-import-keys \
se --provides --match-exact 2>&1| egrep -v "^S|^---|\.\.\."| \
sed 's/^[^|]*| *\([^| ]*\) *.*/\1/'
```

The `ldd` shows what shared libraries the `/usr/bin/zypper` is linked with. The `whereis` tells us where those libraries are and `zypper --non-interactive --no-gpg-checks --gpg-auto-import-key se --provides --match-exact` helps us to find out what exact package provides that shared library.

The next was to figure out what packages will the `rpmbuild` and `rpmspec` binaries will need. The same method does the trick again this time starting with `ldd /usr/bin/rpmbuild`

One seriously annoying issue here was the `krb5`, `libzypp`, `libsolv-tools` and `zypper` packages what silently pulled a bunch of busybox-* packages and later these fake stuff did confuse important process and made me wonder for some time how to convince my chroot that grep is the real grep and not the busybox-grep. And here it is the next gallon of gasoline on the flame-war between rpm and deb because if a naive rpm package depends on a resource (like on `/usr/bin/gawk`) and not on a real package (like on the `gawk` package) then such fake package as busybox-gawk can confuse automatic deployment processes. The learning is that we should always make the dependencies clean and tidy.


### Building the Sysroot
When I first started coding in grammar school, we often joked that brute force is unbeatable. While it's usually a foolish approach, but if we have the time and resources, it sure can produce results. So, when building a chroot rootfs, I used that method.


I went to the http server of the distro packages to find the right packages, downloaded them, and dumped them with `rpm2cpio` and `cpio` to the dedicated work directory where I was building the sysroot. Yes, `rpm` can install to a specific root directory with the `--root` parameter but the sad part of this story is that not all packages support it. The next time anyone enters an otherwise pointless deb vs rpm flamewar, this point can be listed for the deb side.


Once all the assumed dependencies of zypper and bash were dumped to the work directory, I started to get a little nervous. I knew that zypper and rpm do a lot more magic than just unpacking package archives, so I wasn't sure if this Frankenstein sysroot would give me a functional chroot. Long story short, it did. I was not sure if all the features and use cases would work, but at this point, all I needed was a sysroot that I could chroot in and the native zypper of the target that could refresh repositories and install packages, including the very zypper package. So, after the first successful chroot, the first job was to clean up all the rpm2cpio and cpio mess with the first zypper run to reinstall everything in a proper way.


This part does take time, as zypper basically downloads all the already downloaded packages. As I'm writing this post, it occurs to me that maybe I should try to install the already downloaded rpm files ([Rubber Duck](https://en.wikipedia.org/wiki/Rubber_duck_debugging) in action).


After this point, the sysroot is available for chrooting in and out. The next step is to teach it to build packages.

### Building packages: The easy part

Building RPM packages is a relatively simple process, albeit a little untidy and messy. In comparison to Debian, where the sources, package infrastructure, and binary packages are kept separate by `dh_make` and `dpkg-buildpackage`, `rpmbuild` tends to occupy the host's filesystem. It could be just my perception, but all Linux build tools tend to mess up the host system with their build dependencies. To build successfully with rpmbuild, we need to first identify the build dependencies of the package we want to build. The `rpmspec --query --buildrequires` command provides a list of the required packages, and `zypper install` takes care of the rest. Without any file system isolation, this step would install several packages on our host, making maintenance and updates of the host more difficult. Thus, isolation of the builder is really a good idea.

### The implementation

The tool that does all of the above is available here: https://github.com/bzoltan1/sysroot-tools.


The [Readme.md](https://github.com/bzoltan1/sysroot-tools#readme) covers most typical use cases and explains the structure and content of the template files.


For demo purpose I have published a few basic templates for openSUSE arm/x86 and SLES-12-SP5 x86 and SLES-15-SP4 aarch64 and x86.


It is important to note that the SLES templates can be used only with access to the SLES repositories which are behind the firewalls of the SUSE engineering infrastructure. Naturally, the speed of creating a sysroot depends heavily on the quality of the network connection to the repositories. I would suggest playing with it on a machine that is close to the download servers. With a poor network connection, it can be really annoying to observe download timeouts and other problems.


To try out the tool is really simple:
```
git clone https://github.com/bzoltan1/sysroot-tools.git
cd sysroot-tools
sudo ./sysroot create -f openSUSE-Tumbleweed-x86_64-sdk.json
```

Once the sysroot is created it is possible to log in to it:

```
sudo ./sysroot login -f [sysroot json file]
```

Or we can build our rpm package with a single command:
```
sudo ./sysroot build -f [sysroot json file] -p [project diretory]
```

All the logs and build artifacts are available in the file system of the chroot what is by default located under `/var/cache/sysroot/` directory.
  
  
My personal favourite is when I create arm targets and build rpm packages for my [JeOS](https://www.suse.com/products/server/jeos/) based [Raspberry Pi](https://www.raspberrypi.org/) device. All that locally on my openSUSE Tumbleweed x86 laptop.
  
  
The obvious disadvantage of this architecture and using chroot for cross-building is that we need to use lots of sudo commands as chrooting with a regular user is either not possible or not a good idea.
  
  
It is possible to create a user space builder, but that needs to be based on containers like [LXC/LXD](https://linuxcontainers.org/lxd/) or [Podman](https://podman.io/). And that is a different ballgame. Sure, it is more modern, but less permeable or accessible than a rootfs on the host system. Naturally, that statement can be debated. In my view, when creating a customer-grade software development tool, the architecture of containers has more benefits than the disadvantage compared to the chroots. But for personal use for someone who knows and wants to know what is going on with their host systems, the chroot is a good solution.
  
  
I have learned a lot about package dependencies in SUSE Linux distributions, the rpm building process, and the strengths and weaknesses of using chroot for file system isolation. It was also fun, and that's important too.
