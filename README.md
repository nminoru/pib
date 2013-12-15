pib - Pseudo InfiniBand HCA driver
==================================

pib is a software-based InfiniBand HCA driver. It provides uVerbs functions
without real IB HCA & fabric.

pib has the two components.

- pib.ko  Linux kernel module
- libpib  Userspace plug-in module for libibverbs


Limitation
==========

The current version is EXPERIMETNAL.


Supported OS
============

pib supports the following Linux:

* Red Hat Enterprise Linux 6.x
* CentOS 6.x 

pib conflicts with Mellanox OFED.
Mustn't install an environment to deploy Mellanox OFED.


Preparation
===========

Rquired packages:

* rdma
* libibverbs
* kernel-devel

Recommended packages:

* libibverbs-devel
* libibverbs-utils


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
    $ cp -r libpib libpib-0.0.6
    $ tar czvft $(HOME)/rpmbuild/SOURCES/libpib-0.0.6.tar.gz libpib-0.0.6/
    $ cp libpib/libpib.spec $(HOME)/rpmbuild/SPECS/
    $ rpmbuild -bs $(HOME)/rpmbuild/SPECS/libpib.spec

Running
=======

First load some modules which pib.ko is depenent on.

    # modprobe ib_core
    # modprobe ib_uverbs
    # modprobe ib_addr
    # modprobe ib_umad
    # modprobe ib_cm
    # modprobe ib_mad

Next load pib.ko.

    # insmod ./pib.ko

On success, you can use uVerbs.
For instance, ibv_devinfo (includes libibverbs-utils packet) show such an result.

    $ ibv_devinfo
    hca_id: pib_0
            transport:                      InfiniBand (0)
            fw_ver:                         1.1.001
            node_guid:                      000c:2925:551e:0020
            sys_image_guid:                 000c:2925:551e:0010
            vendor_id:                      0x0001
            vendor_part_id:                 1
            hw_ver:                         0x0
            phys_port_cnt:                  2


Future work
===========

My goal is to work the following software components.

* Subnet manager (opensm)
* IPoIB
* RDMA Communictor Manager
* MPI
* iSER

Therefore I will implement the following IB functions.

* SMI (QP0)
* GSI (GP1)
* Multicast
* Unreliable Connection(UC)
* Extended Reliable Connected (XRC)
* Memory Window
* Alternate path

Other

* GRH
* Easy LID assigment without subnet manger.
* Error injection
* Other Linux distributions support
* Kernel update package
* IPv6 support
* Translate Japanese into English in comments of source codes :-)
