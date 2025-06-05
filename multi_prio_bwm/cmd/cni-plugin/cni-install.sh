#!/bin/bash

# put cni-plugin
CNI_DIR="/host/opt/cni/bin"

cd ${CNI_DIR}
cp -r /bwm-cni . || exit 255
