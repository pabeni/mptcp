# SPDX-License-Identifier: GPL-2.0

top_srcdir = ../../../../..

CFLAGS =  -Wall -Wl,--no-as-needed -O2 -g  -iquote../../../../../include/uapi/

TEST_PROGS := mptcp_connect.sh

TEST_GEN_FILES = mptcp_connect pm_nl_ctl

EXTRA_CLEAN := *.pcap

include ../../lib.mk
