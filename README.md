xsplice-build
=============

xsplice-build is a tool for building xSplice patches from source code
patches.  It takes as input, a Xen tree and a patch and outputs an
`.xsplice` module containing containing the live patch.

Quick start
-----------
First checkout the code, and then run `make` to build it.

Here is an example of building a patch for XSA-106:
```
$ cd ~/src/xen
$ git reset --hard
$ git clean -x -f -d
$ git checkout 346d4545569928b652c40c7815c1732676f8587c^
$ cd ~/src/xsplice-build
$ wget -q 'http://xenbits.xen.org/xsa/xsa106.patch'
$ ./xsplice-build --xen-debug -s ~/src/xen -p xsa106.patch -o out
Building xSplice patch: xsa106

Xen directory: /home/ross/src/xen
Patch file: /home/ross/src/xsplice-build/xsa106.patch
Output directory: /home/ross/src/xsplice-build/out
================================================

Testing patch file...
Perform full initial build with 4 CPU(s)...
Apply patch and build with 4 CPU(s)...
Unapply patch and build with 4 CPU(s)...
Extracting new and modified ELF sections...
Processing xen/arch/x86/x86_emulate.o
Creating patch module...
xsa106.xsplice created successfully

$ ls -lh out/xsa106.xsplice
-rw-rw-r--. 1 ross ross 418K Oct 12 12:02 out/xsa106.xsplice
```

Project Status
--------------
This is prototype code:
 * There's no way to apply built patches
 * Patches cannot be built for some source patches
 * The output format does not correspond to the latest xSplice design

With no source patch modifications, live patches can be built for every
XSA that applies to x86 back to XSA-90 except for XSA-97, XSA-111,
XSA-112, and XSA-114 (83% success rate).

License
-------
xSplice is under the GPLv2 license.

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
