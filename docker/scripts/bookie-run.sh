#!/usr/bin/env bash

set -x

function bookkeeper_init() {
  # init the new cluster 
  # (init is an atomic operation using zookeeper multi)
  bookkeeper shell initnewcluster || true

  bookkeeper org.apache.distributedlog.tools.Tool org.apache.distributedlog.admin.DistributedLogAdmin bind \
  -l /ledgers \
  -s ${zkServers} \
  -c distributedlog://${zkServers}/distributedlog || true
}

# apply env variables to the confs
apply-config-from-env.py conf/bookkeeper.conf

bookkeeper_init

# start bookie
exec bin/pulsar bookie
