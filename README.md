pib - Pseudo InfiniBand HCA driver
==================================

pib is a software-based InfiniBand HCA driver.
It provides InfiniBand functions without real IB HCA & fabric.
pib aims to simulate InfiniBand behavior accurately but not to get speed.

pib contains the two components.

- pib.ko - Linux kernel module
- libpib - Userspace plug-in module for libibverbs

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
* Select some implementation dependent behaviours and enforce error checking.
* Show a warning of pithalls that IB programs should avoid. 

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

Debugging support
=================

pib provieds some debugging functions to help developing IB programs.

    # mount -t debugfs none /sys/kernel/debug

/sys/kernel/debug/pib/{pib_0,pib_1,pib_2,pib_3}/


Objection inspection
--------------------

The object inspection displays IB objects.
_ucontext_, _cq_, _pd_, _mr_, _ah_, _srq_ and _qp_

Each IB objects except QP ha an unique number(OID) in creation time.
The OID has a range from 1 to N.
Zero indicates invalid.

The QP's OID is the same as QPN.

_ucontext_ displays a list of ucontext(s).

    OID  CREATIONTIME                               PID   TIG   COMM
    0003 1391600465.758872379 (2014-02-05 11:41:05)  3010  3010 ibv_srq_pingpon

_cq_ displays a list of completion queue(s).

_TYPE_ indicates *NONE*(don't attach completion channel), *SOLI*(solicited only) or *COMP*(all completion).

_NOTIFY_ indicates *NOTIFY* or *WAIT*.

    OID  CREATIONTIME                               S  MAX    CUR   TYPE NOTIFY
    0001 1391600412.870028559 (2014-02-05 11:40:12) OK   1280     0 NONE WAIT
    0004 1391600412.878382628 (2014-02-05 11:40:12) OK    128     9 NONE WAIT

_pd_ displays a list of protection domain(s).

    OID  CREATIONTIME
    0001 1391600791.823835597 (2014-02-05 11:46:31)
    0002 1391600791.832684317 (2014-02-05 11:46:31)

_mr_ displays a list of memory region(s).

_DMA_ indicates *DMA* or *USR*.

    OID  CREATIONTIME                               PD   START            LENGTH           LKEY     RKEY     DMA AC
    0001 1391600412.870147521 (2014-02-05 11:40:12) 0001 0000000000000000 ffffffffffffffff ebb40000 ebb47000 DMA 1
    000f 1391600465.758921144 (2014-02-05 11:41:05) 0007 0000000000e28000 0000000000001000 694ed000 694ee000 USR 1

_ah_ displays a list of address handle(s).

    OID    CREATIONTIME                               PD   DLID AC PORT
    000017 1391600420.365123687 (2014-02-05 11:40:20) 0001 0001  0 1
    000019 1391600420.365679451 (2014-02-05 11:40:20) 0002 0001  0 2
    00001a 1391600422.974130883 (2014-02-05 11:40:22) 0003 c000  1 1
    00001f 1391600422.980053867 (2014-02-05 11:40:22) 0004 c000  1 2

_srq_ displays a list of share receive queue(s).

    OID  CREATIONTIME                               PD   S   MAX   CUR
    0001 1391600791.843958465 (2014-02-05 11:46:31) 0003 OK    256   256
    0002 1391600791.854553879 (2014-02-05 11:46:31) 0004 OK    256   256
    0003 1391600801.525241462 (2014-02-05 11:46:41) 0005 OK    500   500

_qp_ displays a list of queue pair(s).

    OID    CREATIONTIME                               PD   QT  STATE SRQ  MAX-S CUR-S MAX-R CUR-R
    cce848 1391600791.852536098 (2014-02-05 11:46:31) 0003 UD  RTS   0000   128     0   256   256
    cce849 1391600791.866151759 (2014-02-05 11:46:31) 0004 UD  RTS   0000   128     0   256   256
    cce84a 1391600801.525381039 (2014-02-05 11:46:41) 0005 RC  INIT  0003     1     0     0     0
    cce84b 1391600801.525391678 (2014-02-05 11:46:41) 0005 RC  INIT  0003     1     0     0     0


Execution trace
---------------

_trace_ displays execution trace.

Error injection
---------------

You can inject CQ, QP or SRQ aschronous error via _inject_err_.

    $ echo "CQ 0004" > inject_err

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
