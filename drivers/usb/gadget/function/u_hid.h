/* SPDX-License-Identifier: GPL-2.0 */
/*
 * u_hid.h
 *
 * Utility definitions for the hid function
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Author: Andrzej Pietrasiewicz <andrzejtp2010@gmail.com>
 */

#ifndef U_HID_H
#define U_HID_H

#include <linux/usb/composite.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* NaoYun Auth patch v2: 实例层持久暂存结构。
 * struct f_hidg 每次 UDC 重绑都会重建（hidg_alloc），存它里面的数据会丢；
 * f_hid_opts（configfs 函数实例）跨重绑存活，暂存槽放这里才能真正跨软拔插 */
struct f_hid_feat_store {
	spinlock_t		lock;
	struct list_head	queue;		/* 主机下发的质询队列 */
	u8			resp[256][64];	/* 按 Report ID 分槽的 Feature 应答 */
	unsigned int		resp_len[256];
	/* NaoYun Auth patch v3: 每个 ID 的 STALL 重试计数，
	 * GET_REPORT 命中时清零，连续 MISS 时自增，超限降级回零 */
	unsigned int		stall_count[256];
};

struct f_hid_opts {
	struct usb_function_instance	func_inst;
	int				minor;
	unsigned char			subclass;
	unsigned char			protocol;
	unsigned char			no_out_endpoint;
	unsigned short			report_length;
	unsigned short			report_desc_length;
	unsigned char			*report_desc;
	bool				report_desc_alloc;

	/* NaoYun Auth patch v2: 跨重绑持久的 Feature 暂存 */
	struct f_hid_feat_store		*feat;

	/*
	 * Protect the data form concurrent access by read/write
	 * and create symlink/remove symlink.
	 */
	struct mutex			lock;
	int				refcnt;
};

int ghid_setup(struct usb_gadget *g, int count);
void ghid_cleanup(void);

#endif /* U_HID_H */
