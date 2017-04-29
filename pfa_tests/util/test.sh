#!/bin/sh
./init_cgrp.sh
./init_swap.sh
./run_cg.sh ./qsort 10000000
