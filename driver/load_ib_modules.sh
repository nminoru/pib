#! /bin/sh

modprobe ib_core
modprobe ib_uverbs
modprobe ib_addr
modprobe ib_umad
modprobe ib_cm
modprobe ib_mad
# modprobe ib_ipoib
modprobe ib_sa
modprobe iw_cm
modprobe ib_ucm
modprobe rdma_ucm
modprobe rdma_cm
