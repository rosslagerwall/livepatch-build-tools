livepatch-build
=============

livepatch-build is a tool for building LivePatch patches from source code
patches.  It takes as input, a Xen tree and a patch and outputs a
`.livepatch` module containing containing the live patch.

Quick start
-----------
First checkout the code, and then run `make` to build it.

Here is an example of building a live patch for Xen for some XSA.
First build Xen, install it on a host somewhere and reboot:
```
$ cp -r ~/src/xen ~/src/xenbuild
$ cd ~/src/xen/xen
$ make nconfig # Make sure to set CONFIG_LIVEPATCH=y
$ make
$ BUILDID=$(readelf -Wn xen-syms | awk '/Build ID:/ {print $3}')
```

Next, build a live patch, using a patch and the source, build ID, and
.config from the original build:
```
$ cd ~/src/livepatch-build
$ ./livepatch-build -s ~/src/xenbuild -p ~/src/xsa.patch -o out \
    -c ~/src/xen/xen/.config --depends $BUILDID
Building LivePatch patch: xsa

Xen directory: /home/ross/src/xenbuild
Patch file: /home/ross/src/xsa.patch
Output directory: /home/ross/src/livepatch-build-tools/out
================================================

Testing patch file...
Perform full initial build with 4 CPU(s)...
Apply patch and build with 4 CPU(s)...
Unapply patch and build with 4 CPU(s)...
Extracting new and modified ELF sections...
Processing xen/arch/x86/x86_emulate.o
Creating patch module...
xsa.livepatch created successfully

$ ls -lh out/xsa.livepatch
-rwxrwxr-x. 1 ross ross 135K Jun 10 09:32 out/xsa.livepatch
```

Finally, copy the live patch to the host and load it:
```
$ scp out/xsa.livepatch myhost:
$ ssh myhost 'xen-livepatch load xsa.livepatch'
Uploading xsa.livepatch (135840 bytes)
Performing apply:. completed
$ ssh myhost 'xen-livepatch list'
 ID                                     | status
----------------------------------------+------------
xsa                                     | APPLIED
```

Project Status
--------------
Live patches can be built and applied for many changes, including most
XSAs; however, there are still some cases which require changing the
source patch to allow it to be built as a live patch.

This tool currently supports x86 only.

It is intended that some or all of this project will merge back into
kpatch-build rather being maintained as a fork.

Contributing
------------
Please send patches created with `git-format-patch` and an appropriate
Signed-off-by: line to <xen-devel@lists.xen.org>, CCing the maintainers
listed below.

Maintainers
-----------
* Ross Lagerwall <ross.lagerwall@citrix.com>
* Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>

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
