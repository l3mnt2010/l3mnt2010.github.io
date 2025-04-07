---
title: "Contributing to SLE/openSUSE"
subtitle: "What is the path of an upstream fix to a given codestream"
date: 2022-02-19T06:42:50+03:00
tags: ["opensuse", "enerprise linux", "osc", "vim"]
type: post
---
  
The motivation of this post is to demonstrate how easy and logical is the workflow of an upstream change in a project to a given SUSE Linux codestream. I try to write this post in a codestream agnostic way. As I have experienced the workflow from the package maintainer point of view is the same for  SUSE:SLE-15:Update and for  openSUSE:Factory.

### What I want to do

It all starts with a Bugzilla case. For the sake of this exercise I will walk through the process with this bug report: https://bugzilla.suse.com/show_bug.cgi?id=1195126 I use this case because it was a fairly simple, straight forward issue. It is a CVE-2022-0351: vim: uncontrolled recursion in eval7(). This is a  Common Vulnerabilities and Exposures (CVE) what means that somebody has found and published an information-security vulnerabilities and exposures. By classification it is an important issue and as a package maintainer it is not my role to re-evaluate if the issue represents serious threat or not. My goal is to figure out if I can reproduce the issue and if I can find a fix for it.

### How it all starts

Naturally I receive an email notification from Bugzilla about the issue. That is what triggers me to start working on the problem. Naturally if I act slowly I may receive a kind notice from somebody who is waiting for the fix.

As start I branch the codebase I am  going to work on. In my particular case it is the SUSE:SLE-15:Update, but it could be the openSUSE:Factory as well.

```
osc -A https://api.suse.de branch -m 'Fixing #1195126 - CVE-2022-0351: vim: uncontrolled recursion in eval7().' SUSE:SLE-15:Update vim
```

```
osc -A https://api.opensuse.org branch -m 'Fixing #1195126 - CVE-2022-0351: vim: uncontrolled recursion in eval7().' openSUSE:Factory vim
```

And after the branch is created I check out the code

```
osc -A https://api.suse.de co home:bzoltan1:branches:SUSE:SLE-15:Update/vim
```

```
osc -A https://api.opensuse.org co home:bzoltan1:branches:editors/vim
```

Here I would like to note that many developers feed the build server address and credentials, trusted project, etc to their `$HOME/.oscrc file.` I also have that setup but for the sake of clarity in this post I indicate the difference between two codestreams.

### Time to do the real work

For a simple fix like this I expect that the bug report contains some instructions on how to reproduce (1) the issue and often even links a git hash or commit in the upstream codebase (2) where one can find the patch.

1) https://huntr.dev/bounties/8b36db58-b65c-4298-be7f-40b9e37fd161/

2) https://github.com/vim/vim/commit/fe6fb267e6ee5c5da2f41889e4e0e0ac5bf4b89d

Naturally every case is different and one can not expect to be served with ready made reproducers and fixes on a silver plate like me in this particular case. More often it takes more sweat and time to get the fix ready.

The package  source tree contains a set of standard files. The most important two for us now are the tar.gz file of the untouched upstream source code and the spec file for the package.  I need to make five steps:

#### 1. Unpack the tar.gz and make a .orig copy of the upstream source directory

```
tar -zxf vim-8.0.1568.tar.gz
cp vim-8.0.1568 vim-8.0.1568.orig
```

I make the .orig directory to create the patch file once I managed to apply the fix on the source directory. As in distribution packages we very seldom (if ever) change the upstream source tar.gz but instead we create patch files. I call these patches distro patches. Each distro has their own patch sets for their packages. Often they are similar and naturally one can find the same security patches in all well maintained distributions.

#### 2. Build the source code and try to reproduce the bug

Since the bug in our case is about a stack corruption and this kind of memory corruption vulnerabilities can cause bypass protection mechanisms and be successful arbitrary code execution I will build the source with Address Sanitizer

```
CC=gcc CFLAGS="-fsanitize=address -O2" LDFLAGS=-fsanitize=address ./configure --enable-gui=none --with-features=huge
make -j$(nproc)
```

Not all cases require such measure and the project may build in a different way. Reading the fine manual usually helps. 

Naturally it is important to build the source in the right environment. In this post I do not cover it but one need to have access to the right development environment. Usually a chroot, container, vm or a dedicated build server is what we use. In case of openSUSE maintenance I have easy job as my main OS is openSUSE Tumbleweed.

Once I have the binaries I can try to reproduce the bug

#### 3. Fix the bug, apply the upstream patch and create the distro patch

That is where the .orig directory comes handy. To fix the bug I needed to modify two files, the src/globals.h and the src/eval.c so creating the vim-8.0.1568-CVE-2022-0351.patch file I need these two commands:

```
diff -u vim-8.0.1568.orig/src/globals.h vim-8.0.1568/src/globals.h >vim-8.0.1568-CVE-2022-0351.patch
diff -u vim-8.0.1568.orig/src/eval.c vim-8.0.1568/src/eval.c >> vim-8.0.1568-CVE-2022-0351.patch
```
#### 4. Take care of package housekeeping and push the package for a test build

I add the patch file to the `vim.spec` file. It is rather unlikely that my patch is the first distro patch so it is easy to find where these two lines should be added

```
 [...]

Patch106: vim-8.0.1568-CVE-2022-0351.patch

 [...]

%patch106 -p1

 [...]
```

Naturally I need to add the patch file to the project and push for a build

```
osc add vim-8.0.1568-CVE-2022-0351.patc
```

and push for a build to the right build server, depending on the target codebase

```
osc -A https://api.opensuse.org commit -m "Fixing #1195126 CVE-2022-0351: vim: uncontrolled recursion in eval7()"
```

```
osc -A https://api.suse.de commit -m "Fixing #1195126 CVE-2022-0351: vim: uncontrolled recursion in eval7()"
```

#### 5. Submit a request

If all goes well so far then all I need is to submit my request for the change and look for the feedback. 

```
osc -A https://api.opensuse.org submitrequest -m 'Fixing #1195126 CVE-2022-0351: vim: uncontrolled recursion in eval7()'
```

```
osc -A https://api.suse.de submitrequest -m 'Fixing #1195126 CVE-2022-0351: vim: uncontrolled recursion in eval7()'
```

The submit request command will return a unique request ID. This ID I can follow on the build system and see if the administrators ask for any change or improvement.

### Summary

All in all, I believe I can make a point here that contributing to SLE or to openSUSE is really not a rocket science. The workflow is straight forward and the tools are easy to use.


### Valuable sources of information
* https://en.opensuse.org/openSUSE:How_to_contribute_to_Factory

* https://openbuildservice.org/help/manuals/obs-user-guide/art.obs.bg.html



