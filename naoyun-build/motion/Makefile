# naoyun_motion — 盒端鼠标出帧内核模块
#
# 编译方式与现役 usb_f_hid.ko 同源（盒上现编，不做交叉编译）。
#
# **必须用 clang/LLVM，不能用 gcc**：`.7` 现网实测这台内核是
# `CONFIG_CC_IS_CLANG=y` + `CONFIG_LTO_CLANG_THIN=y`，内核 Makefile 会无条件把
# `-Qunused-arguments`、`-mno-global-merge`、`-flto=thin -fsplit-lto-unit` 这些 clang 专用
# flag 塞进 KBUILD_CFLAGS（Makefile 第 812/818/963 行）⇒ gcc 直接 `unrecognized command-line
# option` 死在第一步。现役那份打过 auth 埋点的 usb_f_hid.ko 里 `.comment` 就是
# "Debian clang version 14.0.6"，说明这条链本来就是这么走的，不是我的新发明。
#
# KDIR 由调用方按"哪个存在"决定：本盒 `/lib/modules/$(uname -r)/build` 指向 /usr/src/
# （没有顶层 Makefile，直接拿它编会失败），真身在 /usr/src/linux-headers-$(uname -r)。
obj-m += naoyun_motion.o

KDIR ?= /lib/modules/$(shell uname -r)/build
CC     ?= clang
LD     ?= ld.lld
LLVM   ?= 1

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) LD=$(LD) LLVM=$(LLVM) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) CC=$(CC) LD=$(LD) LLVM=$(LLVM) clean

.PHONY: all clean
