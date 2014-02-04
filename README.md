pib - Pseudo InfiniBand HCA driver
==================================

pib is a software-based InfiniBand HCA driver.
It provides InfiniBand functions without real IB HCA & fabric.

pib aims to be accurate IB simulator to assist developers

pib contains the two components.

- pib.ko - Linux kernel module
- libpib - Userspace plug-in module for libibverbs

Features
========

In single-host-mode, pib creates up to 4 InfiniBand HCA (The default is 2).
These IB devices are pib_0, pib_1, pib_2 and pib_3.
Each HCA contains up to 32 ports (The default is 2).

In addition, pib creates single internal InfiniBand switch too.
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

* Inspect IB objects (ucontext, protection domain, MR, SRQ, CQ, AH, QP)
* Error injection (QP/CQ/SRQ Error)
* Execution trace (API invocation, packet sending/receiving, async event)
* Select some implementation dependent behaviours and enforce error checking.
* Show a warning of pithalls that programs should avoid. 

Other features:

* The maximum size of inline data is 2048 bytes.

Limitation
==========

The current version is EXPERIMETNAL and not supported multi host mode.

The follwing features are not supported:

- Unreliable Datagram (UD)
- Fast Memory Region (FMR)
- Memory Windows (MR)
- SEND Invalidate operation
- Virtual Lane (VL)

Supported OS
============

pib supports the following Linux:

* Red Hat Enterprise Linux 6.x
* CentOS 6.x 

pib conflicts with Mellanox OFED.
Mustn't install an environment to deploy Mellanox OFED.

Preparation
===========

The following software packeages are required for building pib:

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

pib.ko
------

    $ cd pib/driver/
    $ make

libpib
------

Source and binary packages for RHEL6 or CentOS6 are avaiable on this link http://www.nminoru.jp/~nminoru/network/infiniband/src/

To build source packages from source code

    $ cd pib
    $ cp -r libpib libpib-0.2.8
    $ tar czvft $(HOME)/rpmbuild/SOURCES/libpib-0.2.8.tar.gz libpib-0.2.8/
    $ cp libpib/libpib.spec $(HOME)/rpmbuild/SPECS/
    $ rpmbuild -bs $(HOME)/rpmbuild/SPECS/libpib.spec

Loading
=======

First, load some modules which pib.ko is depenent on.

    # /etc/rc.d/init.d/rdma start

Next, load pib.ko.

    # insmod ./pib.ko

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

IB Objection inspection
-----------------------

    # mount -t debugfs nodev /sys/kernel/debug

Future work
===========

Multi host support
------------------
For multi host mode, I'm planning to develop an InfiniBand fabric simulater like ibsim.

IB functions
------------

* Unreliable Connection(UC)
* Extended Reliable Connected (XRC)
* Memory Window
* Alternate path

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

* Other Linux distributions support
* Kernel update package
* IPv6 support
* Translate Japanese into English in comments of source codes :-)
