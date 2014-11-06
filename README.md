pib - Pseudo InfiniBand HCA driver
==================================

pib is a software-based InfiniBand HCA driver.
It provides InfiniBand functions without real IB HCA & fabric.
pib aims to simulate InfiniBand behavior accurately but not to get speed.

pib contains the three components.

- pib.ko  - Linux kernel module
- libpib  - Userspace plug-in module for libibverbs
- pibnetd - IB switch emulator for multi-host-mode

Features
========

In single-host-mode, pib creates up to 4 InfiniBand HCA (The default is 2).
These IB devices are pib_0, pib_1, pib_2 and pib_3.
Each HCA contains up to 32 ports (The default is 2).

In addition, pib creates one internal InfiniBand switch too.
All ports of pib's HCA are connected to this switch.

The current version of pib enables to drive the following interface:

* kernel-level Verbs (in-linux kernel)
* kernel-level MAD (in-linux kernel)
* uVerbs (libibverbs)
* uMAD (libibmad & libibumad)
* Subnet Manager (opensm)
* IPoIB (in-linux kernel)
* RDMA Connection Manager (librdmacm)
* IB diagnostic utilities (infiniband-diags)

Debugging support features:

* Inspect IB objects (ucontext, PD, MR, SRQ, CQ, AH, QP)
* Trace API invocations, packet sending/receiving, async events/errors
* Inject a specified error (QP/CQ/SRQ Error)
* Select some implementation dependent behaviour and enforce error checking.
* Show a warning of pitfalls that IB programs should avoid.

Other features:

* The maximum size of inline data is 2048 bytes.

Limitation
==========

The current version is EXPERIMENTAL.

The following features are not supported:

- Unreliable Connected (UC)
- Fast Memory Region (FMR)
- Memory Windows (MW)
- SEND Invalidate operation
- Virtual Lane (VL)
- Flow control

Supported OS
============

pib supports the following Linux:

* Red Hat Enterprise Linux 6.x
* CentOS 6.x 

pib conflicts with Mellanox OFED.
Mustn't install an environment to deploy Mellanox OFED.

Preparation
===========

The following software packages are required for building pib:

* rdma
* libibverbs
* kernel-devel
* opensm
* opensm-libs

The following packages are recommended:

* libibverbs-devel (for developing Verbs API programs)
* libibverbs-utils
* librdmacm
* librdmacm-utils
* librdmacm-devel (for developing RDMA API programs)
* infiniband-diags (IB diagnostic tools)

Building
========

First, acquire the source code by cloning the git repository.

    $ git clone https://github.com/nminoru/pib.git

pib.ko
------

If you want to compile the pib.ko kernel module from source code, input the following commands.

    $ cd pib/driver/
    $ make
    # make modules_install

If you want to create binary RPM file, input the following commands.

First, create libpib's source RPM from source code.

    $ cp -r pib/driver pib-0.4.5
    $ tar czvf $(HOME)/rpmbuild/SOURCES/pib-0.4.5.tar.gz pib-0.4.5/
    $ cp pib/driver/pib.spec $(HOME)/rpmbuild/SPECS/
    $ rpmbuild -bs $(HOME)/rpmbuild/SPECS/pib.spec

Next, build the binary RPM from the source RPM.

    $ rpmbuild --rebuild $(HOME)/rpmbuild/SRPMS/pib-0.4.5-1.el6.src.rpm

Finally, install the built binary RPM.

    # rpm -ihv $(HOME)/rpmbuild/RPMS/x86_64/kmod-pib-0.4.5-1.el6.x86_64.rpm

libpib
------

The libpib userspace plug-in module will be installed from the binary RPM. 

    $ cp -r pib/libpib libpib-0.0.6
    $ tar czvf $(HOME)/rpmbuild/SOURCES/libpib-0.0.6.tar.gz libpib-0.0.6/
    $ cp pib/libpib/libpib.spec $(HOME)/rpmbuild/SPECS/
    $ rpmbuild -bs $(HOME)/rpmbuild/SPECS/libpib.spec

    $ rpmbuild --rebuild $(HOME)/rpmbuild/SRPMS/libpib-0.0.6-1.el6.src.rpm

    # rpm -ihv $(HOME)/rpmbuild/RPMS/x86_64/libpib-0.0.6-1.el6.x86_64.rpm

pibnetd
-------

If you want to compile the pibnetd daemon from source code, input the following commands.

    $ cd pib/pibnet/
    $ make
    # install -m 755 -D pibnetd                     /usr/sbin/pibnetd
    # install -m 755 -D scripts/redhat-pibnetd.init /etc/rc.d/init.d/pibnetd

If you want to create binary RPM file, input the following commands.

    $ cp -r pib/pibnetd pibnetd-0.4.0
    $ tar czvf $(HOME)/rpmbuild/SOURCES/pibnetd-0.4.0.tar.gz pibnetd-0.4.0/
    $ cp pib/pibnetd/pibnetd.spec $(HOME)/rpmbuild/SPECS/
    $ rpmbuild -bs $(HOME)/rpmbuild/SPECS/pibnetd.spec

    $ rpmbuild --rebuild $(HOME)/rpmbuild/SRPMS/pibnetd-0.4.0-1.el6.src.rpm

    # rpm -ihv $(HOME)/rpmbuild/RPMS/x86_64/pibnetd-0.4.0-1.el6.x86_64.rpm

Download
--------

You can get source and binary RPMs for RHEL6 or CentOS6 on this link http://www.nminoru.jp/~nminoru/network/infiniband/src/

Loading (single-host-mode)
==========================

First, load some modules which pib.ko is dependent on.

    # /etc/rc.d/init.d/rdma start

Next, load pib.ko.

    # modprobe pib

Finally, run opensm

    # /etc/rc.d/init.d/opensm start

pib.ko options
--------------

* debug_level
* num_hca
* phys_port_cnt
* behavior
* manner_warn
* manner_err
* addr

Loading (multi-host-mode)
=========================

In multi-host-mode mode, pib enables to connect up to 32 hosts (To be precise, up to 32 ports).

       Host A           Host X           Host B
     (10.0.0.1)       (10.0.0.2)       (10.0.0.3)
    +----------+     +-----------+     +----------+
    | +------+ |     | +-------+ |     | +------+ |
    | |pib.ko| |-----| |pibnetd| |-----| |pib.ko| |
    | +------+ |     | +-------+ |     | +------+ |
    |          |     |           |     | +------+ |
    |          |     |           |     | |opensm| |
    |          |     |           |     | +------+ | 
    +----------+     +-----------+     +----------+ 

First, run pibnetd on a host.

    # /etc/rc.d/init.d/pibnetd start

Next, load pib.ko by running modprobe command with the _addr_ parameter specified by the pibnetd's IP address.

    # /etc/rc.d/init.d/rdma start
    # modprobe pib addr=10.0.0.2

On th default parameters, pib creates 2 IB devices of 2 ports.
You had better limit 1 IB device of 1 port by specifying the _num_hca_ and _phys_port_cnt_ parameters in multi-host-mode.

    # modprobe pib addr=10.0.0.2 num_hca=1 phys_port_cnt=1

Finally, run opensm on one of hosts that load pib.ko.

    # /etc/rc.d/init.d/opensm start

Running
=======

For instance, ibv_devinfo (includes libibverbs-utils package) show such an result.

    $ ibv_devinfo
    hca_id: pib_0
            transport:                      InfiniBand (0)
            fw_ver:                         0.2.000
            node_guid:                      000c:2925:551e:0400
            sys_image_guid:                 000c:2925:551e:0200
            vendor_id:                      0x0001
            vendor_part_id:                 1
            hw_ver:                         0x0
            phys_port_cnt:                  2

Performance counter
-------------------

    # perfquery

Debugging support
=================

pib provides some debugging functions via debugfs to help developing IB programs.

First ensure that debugfs is mounted.

    # mount -t debugfs none /sys/kernel/debug

A list of available debugging functions can be found in /sys/kernel/debug/pib/pib_X/.

See detailed information on DEBUGFS.md.


Future work
===========

IB functions
------------

* Fast Memory Registration(FMR)
* Peer-Direct
* Alternate path
* Unreliable Connection(UC)
* Extended Reliable Connected (XRC)
* Memory Window

Debugging support
-----------------

* Packet filtering

Software components
-------------------

* MPI
* User Direct Access Programming Library (uDAPL)
* iSCSI Extensions for RDMA (iSER)
* SCSI RDMA Protocol (SRP)

Other
-----

* Systemd init script support
* Other Linux distributions support
* Kernel update package
* IPv6 support
* Translate Japanese into English in comments of source codes :-)
