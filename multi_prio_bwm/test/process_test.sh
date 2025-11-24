#!/bin/bash

# process test
cd process_test
cd egress
sh -x process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219
sleep 10
sh -x process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 512 1
sleep 10
sh -x process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 128KB 64
sleep 10
sh -x process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 512 64
sleep 10

cd ../ingress
sh -x process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54
sleep 10
sh -x process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 512 1
sleep 10
sh -x process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 128KB 64
sleep 10
sh -x process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 512 64
sleep 10

# process mix test
cd ../mix_test
sh -x ../egress/process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 &
sh -x ../ingress/process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 &
sleep 80

sh -x ../egress/process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 512 1 &
sh -x ../ingress/process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 512 1 &
sleep 80

sh -x ../egress/process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 128KB 64 &
sh -x ../ingress/process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 128KB 64 &
sleep 80

sh -x ../egress/process-bwm-test-egress.sh  1000 1 500 2 200 1 10 7.6.122.54 7.6.122.219 512 64 &
sh -x ../ingress/process-bwm-test-ingress.sh 1000 1 500 2 200 1 10 7.6.122.219 7.6.122.54 512 64 &
sleep 80

