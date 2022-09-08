#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright 2022, The ChromiumOS Authors.

# Regression tests for behavior seen when mounting additional debugfs or
# tracefs instances. Ref:
#
# debugfs: Only clobber mode/uid/gid on remount if asked
# https://git.kernel.org/linus/b8de524ce46ef59889600bc29019c5ed4ccd6687
# Present in v6.1-rc1
#
# tracefs: Only clobber mode/uid/gid on remount if asked
# https://git.kernel.org/linus/47311db8e8f33011d90dee76b39c8886120cdda4
# Present in v6.0-rc5

TST_CNT=9
TST_CLEANUP=cleanup
TST_SETUP=setup
TST_TESTFUNC=test
TST_NEEDS_ROOT=1
TST_NEEDS_CMDS="awk chmod chown mount umount"


# Arg 1: filesystem type.
is_fs_supported() {
	grep -q "\<$1$" /proc/filesystems
}

# Arg 1: filesystem type.
count_mounts() {
	awk '
		BEGIN { COUNT = 0; }
		$3=="'$1'" { COUNT += 1; }
		END { print COUNT; }
	' /proc/mounts
}

# Arg 1: filesystem type.
umount_all() {
	local fstype="$1"
	for mountpoint in \
		$(awk '$3=="'${fstype}'" { print $2; }' /proc/mounts)
	do
		umount "${mountpoint}" || return $?
	done
	[ "$(count_mounts ${fstype})" -eq 0 ] || return 1
}

assert_mode() {
	local path="$1"
	local mode="$2"
	local res

	res="$(stat -c '%a' "${path}")"
	if [ $? -ne 0 ]; then
		tst_res TBROK "couldn't check permissions on \"${path}\""
		return 1
	fi

	if [ "${res}" != "${mode}" ]; then
		tst_res TFAIL "path \"${path}\" has mode \"${res}\"; expected \"${mode}\""
		return 1
	fi
}

assert_user_group() {
	local path="$1"
	local user="$2"
	local group="$3"
	local res

	res="$(stat -c '%U:%G' "${path}")"
	if [ $? -ne 0 ]; then
		tst_res TBROK "couldn't check user/group on \"${path}\""
		return 1
	fi

	if [ "${res}" != "${user}:${group}" ]; then
		tst_res TFAIL "path \"${path}\" has user:group \"${res}\"; expected \"${user}:${group}\""
		return 1
	fi
}

cleanup() {
	userdel mntacl2
	userdel mntacl1
}

setup() {
	if ! is_fs_supported debugfs; then
		tst_brk TCONF "Must have debugfs support"
	fi

	if ! is_fs_supported tracefs; then
		tst_brk TCONF "Must have tracefs support"
	fi

	if ! umount_all debugfs; then
		tst_brk TBROK "Couldn't unmount debugfs"
	fi

	if ! umount_all tracefs; then
		tst_brk TBROK "Couldn't unmount tracefs"
	fi

	useradd -M mntacl1 || tst_brk TBROK "Couldn't add user"
	useradd -M mntacl2 || tst_brk TBROK "Couldn't add user"

	# Set initial tracefs mount. Specify all options (uid/gid/mode)
	# explicitly to the kernel defaults, because these persist across
	# mounts (and therefore across tests).
	mount -t tracefs -o uid=root,gid=root,mode=700 \
		tracefs /sys/kernel/tracing || \
		tst_brk TBROK "Couldn't mount tracefs"

	mount -t debugfs debugfs /sys/kernel/debug || \
		tst_brk TBROK "Couldn't mount debugfs"
}

## --- Tests! ---

test1() {
	local res

	chmod 755 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing permissions"
		return 1
	}
	assert_mode /sys/kernel/tracing 755 || return 1
	res="$(count_mounts tracefs)"
	if [ "${res}" -ne 1 ]; then
		tst_res TBROK "Unexpected mounts: ${res} != 1"
		return 1
	fi
	# The 'stat' triggers an automount.
	stat /sys/kernel/debug/tracing/. >/dev/null || {
		tst_res TBROK "Couldn't stat tracing"
		exit 1
	}
	res="$(count_mounts tracefs)"
	if [ "${res}" -ne 2 ]; then
		tst_res TBROK "Unexpected mounts: ${res} != 2"
		return 1
	fi
	assert_mode /sys/kernel/debug/tracing 755 || return 1
	assert_mode /sys/kernel/tracing 755 || return 1

	tst_res TPASS "tracefs automount keeps permissions"
}

test2() {
	chmod 755 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing permissions"
		return 1
	}
	umount /sys/kernel/tracing || {
		tst_res TBROK "Failed to unmount tracing"
		return 1
	}
	mount -t tracefs -o mode=750 tracefs /sys/kernel/tracing || {
		tst_res TBROK "Failed to mount tracing"
		return 1
	}
	assert_mode /sys/kernel/tracing 750 || return 1
	assert_mode /sys/kernel/debug/tracing 750 || return 1

	tst_res TPASS "tracefs mode option overrides"
}

test3() {
	chmod 750 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing owner"
		return 1
	}
	umount /sys/kernel/tracing || {
		tst_res TBROK "Failed to unmount tracing"
		return 1
	}
	mount -t tracefs -o uid=mntacl1 tracefs /sys/kernel/tracing || {
		tst_res TBROK "Failed to mount tracing"
		return 1
	}
	assert_mode /sys/kernel/tracing 750 || return 1
	assert_mode /sys/kernel/debug/tracing 750 || return 1
	assert_user_group /sys/kernel/tracing mntacl1 mntacl2
	assert_user_group /sys/kernel/debug/tracing mntacl1 mntacl2

	tst_res TPASS "tracefs uid option overrides"
}

test4() {
	chmod 750 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing owner"
		return 1
	}
	umount /sys/kernel/tracing || {
		tst_res TBROK "Failed to unmount tracing"
		return 1
	}
	mount -t tracefs -o gid=mntacl1 tracefs /sys/kernel/tracing || {
		tst_res TBROK "Failed to mount tracing"
		return 1
	}
	assert_mode /sys/kernel/tracing 750 || return 1
	assert_mode /sys/kernel/debug/tracing 750 || return 1
	assert_user_group /sys/kernel/tracing mntacl2 mntacl1
	assert_user_group /sys/kernel/debug/tracing mntacl2 mntacl1

	tst_res TPASS "tracefs gid option overrides"
}

test5() {
	chmod 750 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/tracing || {
		tst_res TBROK "Failed to set tracing owner"
		return 1
	}
	umount /sys/kernel/tracing || {
		tst_res TBROK "Failed to unmount tracing"
		return 1
	}
	mount -t tracefs -o mode=770,uid=root,gid=mntacl1 tracefs /sys/kernel/tracing || {
		tst_res TBROK "Failed to mount tracing"
		return 1
	}
	assert_mode /sys/kernel/tracing 770 || return 1
	assert_mode /sys/kernel/debug/tracing 770 || return 1
	assert_user_group /sys/kernel/tracing root mntacl1
	assert_user_group /sys/kernel/debug/tracing root mntacl1

	tst_res TPASS "tracefs mode+uid+gid option overrides"
}

test6() {
	chmod 700 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs owner"
		return 1
	}
	umount -R /sys/kernel/debug || {
		tst_res TBROK "Failed to unmount debugfs"
		return 1
	}
	mount -t debugfs -o mode=750 debugfs /sys/kernel/debug || {
		tst_res TBROK "Failed to mount debugfs"
		return 1
	}
	assert_mode /sys/kernel/debug 750 || return 1

	tst_res TPASS "debugfs mode option overrides"
}

test7() {
	chmod 750 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs owner"
		return 1
	}
	umount /sys/kernel/debug || {
		tst_res TBROK "Failed to unmount debugfs"
		return 1
	}
	mount -t debugfs -o uid=mntacl1 debugfs /sys/kernel/debug || {
		tst_res TBROK "Failed to mount debugfs"
		return 1
	}
	assert_mode /sys/kernel/debug 750 || return 1
	assert_user_group /sys/kernel/debug mntacl1 mntacl2

	tst_res TPASS "debugfs uid option overrides"
}

test8() {
	chmod 750 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs owner"
		return 1
	}
	umount /sys/kernel/debug || {
		tst_res TBROK "Failed to unmount debugfs"
		return 1
	}
	mount -t debugfs -o gid=mntacl1 debugfs /sys/kernel/debug || {
		tst_res TBROK "Failed to mount debugfs"
		return 1
	}
	assert_mode /sys/kernel/debug 750 || return 1
	assert_user_group /sys/kernel/debug mntacl2 mntacl1

	tst_res TPASS "debugfs gid option overrides"
}

test9() {
	chmod 750 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs permissions"
		return 1
	}
	chown mntacl2:mntacl2 /sys/kernel/debug || {
		tst_res TBROK "Failed to set debugfs owner"
		return 1
	}
	umount /sys/kernel/debug || {
		tst_res TBROK "Failed to unmount debugfs"
		return 1
	}
	mount -t debugfs -o mode=770,uid=root,gid=mntacl1 debugfs /sys/kernel/debug || {
		tst_res TBROK "Failed to mount debugfs"
		return 1
	}
	assert_mode /sys/kernel/debug 770 || return 1
	assert_user_group /sys/kernel/debug root mntacl1

	tst_res TPASS "debugfs mode+uid+gid option overrides"
}

. tst_test.sh
tst_run
