livepatch-build
=============

livepatch-build is a tool for building LivePatch patches from source code
patches.  It takes as input, a Xen tree and a patch and outputs an
`.livepatch` module containing containing the live patch.

Quick start
-----------
First checkout the code, and then run `make` to build it.

Here is an example of building a patch for XSA-106:
```
$ cd ~/src/xen
$ git reset --hard
$ git clean -x -f -d
$ git checkout 346d4545569928b652c40c7815c1732676f8587c^
$ cd ~/src/livepatch-build
$ wget -q 'http://xenbits.xen.org/xsa/xsa106.patch'
$ ./livepatch-build --xen-debug -s ~/src/xen -p xsa106.patch -o out
Building LivePatch patch: xsa106

Xen directory: /home/ross/src/xen
Patch file: /home/ross/src/livepatch-build/xsa106.patch
Output directory: /home/ross/src/livepatch-build/out
================================================

Testing patch file...
Perform full initial build with 4 CPU(s)...
Apply patch and build with 4 CPU(s)...
Unapply patch and build with 4 CPU(s)...
Extracting new and modified ELF sections...
Processing xen/arch/x86/x86_emulate.o
Creating patch module...
xsa106.livepatch created successfully

$ ls -lh out/xsa106.livepatch
-rw-rw-r--. 1 ross ross 418K Oct 12 12:02 out/xsa106.livepatch
```

Project Status
--------------
Live patches can be built and applied for most XSAs; however, there are
still some cases which require changing the source patch to support
being built as a live patch.

This tool currently supports x86 only.

It is intended that some or all of this project will merge back into
kpatch-build rather being maintained as a fork.

License
-------
LivePatch is under the GPLv2 license.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Credits
-------
Most of this code is copied from [kPatch](https://github.com/dynup/kpatch).
All credits to the kPatch authors.
