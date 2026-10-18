// SPDX-License-Identifier: GPL-2.0+
/*
 * f_hid.c -- USB HID function driver
 *
 * Copyright (C) 2010 Fabien Chouteau <fabien.chouteau@barco.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hid.h>
#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/uio.h>		/* NaoYun Auth patch v4: copy_from_iter / iov_iter_count */
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/usb/g_hid.h>

#include "u_f.h"
#include "u_hid.h"

#define HIDG_MINORS	4

static int major, minors;
static struct class *hidg_class;
static DEFINE_IDA(hidg_ida);
static DEFINE_MUTEX(hidg_ida_lock); /* protects access to hidg_ida */

/*-------------------------------------------------------------------------*/
/*                            HID gadget struct                            */

struct f_hidg_req_list {
	struct usb_request	*req;
	unsigned int		pos;
	struct list_head 	list;
};

/* NaoYun Auth patch: PS5 DualSense Feature Report 用户态中继通道
 * 质询(0x80/0xF0)经 SET_REPORT/OUT 端点到达 -> 入队供用户态 read() 取走；
 * 用户态 write() 首字节为 0x80 或 >= 0xF0 的报文视为 Feature 应答(0xF1/0xF2)，
 * 存入应答缓冲供主机 GET_REPORT 读取（原版固定回全零导致 PS5 认证失败）。
 * 实证：PS5 实测下发的质询 SET_REPORT 首字节为 0x80（描述符 0x80 Feature 63B），
 * 并非公开资料描述的 0xF0，两者都必须入队。 */
struct f_hidg_feat {
	char			*buf;
	unsigned int		len;
	struct list_head	list;
};

struct f_hidg {
	/* configuration */
	unsigned char			bInterfaceSubClass;
	unsigned char			bInterfaceProtocol;
	unsigned char			protocol;
	unsigned char			idle;
	unsigned short			report_desc_length;
	char				*report_desc;
	unsigned short			report_length;
	/*
	 * use_out_ep - if true, the OUT Endpoint (interrupt out method)
	 *              will be used to receive reports from the host
	 *              using functions with the "intout" suffix.
	 *              Otherwise, the OUT Endpoint will not be configured
	 *              and the SETUP/SET_REPORT method ("ssreport" suffix)
	 *              will be used to receive reports.
	 */
	bool				use_out_ep;

	/* recv report */
	spinlock_t			read_spinlock;
	wait_queue_head_t		read_queue;
	/* recv report - interrupt out only (use_out_ep == 1) */
	struct list_head		completed_out_req;
	unsigned int			qlen;
	/* recv report - setup set_report only (use_out_ep == 0) */
	char				*set_report_buf;
	unsigned int			set_report_length;

	/* send report */
	spinlock_t			write_spinlock;
	bool				write_pending;
	wait_queue_head_t		write_queue;
	struct usb_request		*req;

	struct device			dev;
	struct cdev			cdev;
	struct usb_function		func;

	struct usb_ep			*in_ep;
	struct usb_ep			*out_ep;

	/* NaoYun Auth patch v2: 指向实例层持久暂存（opts->feat）。
	 * struct f_hidg 每次 UDC 重绑都重建，预置的 Feature 应答必须存在
	 * configfs 函数实例（f_hid_opts）里才能跨软拔插存活 */
	struct f_hid_feat_store		*feat;
};

static inline struct f_hidg *func_to_hidg(struct usb_function *f)
{
	return container_of(f, struct f_hidg, func);
}

/* NaoYun Auth patch v2: 真 DualSense 描述符中的全部 Feature Report ID
 * （0x05 校准 / 0x09 配对 / 0x20 固件信息 / 0x80-0x81 PS5 实测质询对 / 0xF0-0xF2 Auth），
 * 这些 ID 的 write() 一律进暂存槽供 GET_REPORT 返回，其余 ID 维持原 IN 端点路径 */
static inline bool hidg_feat_id(u8 id)
{
	switch (id) {
	case 0x05:
	case 0x08:
	case 0x09:
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x80:
	case 0x81:
		return true;
	default:
		return id >= 0xF0;
	}
}

/* NaoYun Auth patch: 质询/中继报文 ID 判定（入队与应答暂存共用）：
 * 0x80 = PS5 实测质询 ID；>= 0xF0 = 公开协议 Auth 族（0xF0 质询/0xF1 签名/0xF2 就绪） */
static inline bool hidg_feat_relay_id(u8 id)
{
	return id == 0x80 || id >= 0xF0;
}

/* NaoYun Auth patch v3: Auth 签名 ID，GET_REPORT 时若响应未到则 STALL 等重试，
 * 而非像 v2 那样立即返回全零。STALL 给源端求解+中继争取时间（~9ms）。
 * PS5 对控制端点 STALL 会自动重试，最多 stall N 次后降级回零防死循环 */
#define HIDG_STALL_MAX  20
static inline bool hidg_feat_stall_id(u8 id)
{
	return id == 0x81;
}

static void hidg_release(struct device *dev)
{
	struct f_hidg *hidg = container_of(dev, struct f_hidg, dev);

	kfree(hidg->report_desc);
	kfree(hidg->set_report_buf);
	kfree(hidg);
}

/* NaoYun Auth patch: 质询入队（单队列，新质询覆盖旧质询——PS5 只认最新一轮） */
static void hidg_feat_queue(struct f_hidg *hidg, const u8 *data,
			    unsigned int len)
{
	struct f_hidg_feat *feat, *old, *tmp;
	unsigned long flags;

	feat = kzalloc(sizeof(*feat), GFP_ATOMIC);
	if (!feat)
		return;
	feat->buf = kmemdup(data, len, GFP_ATOMIC);
	if (!feat->buf) {
		kfree(feat);
		return;
	}
	feat->len = len;

	spin_lock_irqsave(&hidg->feat->lock, flags);
	list_for_each_entry_safe(old, tmp, &hidg->feat->queue, list) {
		list_del(&old->list);
		kfree(old->buf);
		kfree(old);
	}
	list_add_tail(&feat->list, &hidg->feat->queue);
	spin_unlock_irqrestore(&hidg->feat->lock, flags);

	pr_info_ratelimited("hidg: feature report queued id=0x%02x len=%u\n",
			    data[0], len);
	wake_up(&hidg->read_queue);
}

/*-------------------------------------------------------------------------*/
/*                           Static descriptors                            */

static struct usb_interface_descriptor hidg_interface_desc = {
	.bLength		= sizeof hidg_interface_desc,
	.bDescriptorType	= USB_DT_INTERFACE,
	/* .bInterfaceNumber	= DYNAMIC */
	.bAlternateSetting	= 0,
	/* .bNumEndpoints	= DYNAMIC (depends on use_out_ep) */
	.bInterfaceClass	= USB_CLASS_HID,
	/* .bInterfaceSubClass	= DYNAMIC */
	/* .bInterfaceProtocol	= DYNAMIC */
	/* .iInterface		= DYNAMIC */
};

static struct hid_descriptor hidg_desc = {
	.bLength			= sizeof hidg_desc,
	.bDescriptorType		= HID_DT_HID,
	.bcdHID				= cpu_to_le16(0x0101),
	.bCountryCode			= 0x00,
	.bNumDescriptors		= 0x1,
	/*.desc[0].bDescriptorType	= DYNAMIC */
	/*.desc[0].wDescriptorLenght	= DYNAMIC */
};

/* Super-Speed Support */

static struct usb_endpoint_descriptor hidg_ss_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_ss_ep_comp_descriptor hidg_ss_in_comp_desc = {
	.bLength                = sizeof(hidg_ss_in_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,

	/* .bMaxBurst           = 0, */
	/* .bmAttributes        = 0, */
	/* .wBytesPerInterval   = DYNAMIC */
};

static struct usb_endpoint_descriptor hidg_ss_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_ss_ep_comp_descriptor hidg_ss_out_comp_desc = {
	.bLength                = sizeof(hidg_ss_out_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,

	/* .bMaxBurst           = 0, */
	/* .bmAttributes        = 0, */
	/* .wBytesPerInterval   = DYNAMIC */
};

static struct usb_descriptor_header *hidg_ss_descriptors_intout[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_comp_desc,
	(struct usb_descriptor_header *)&hidg_ss_out_ep_desc,
	(struct usb_descriptor_header *)&hidg_ss_out_comp_desc,
	NULL,
};

static struct usb_descriptor_header *hidg_ss_descriptors_ssreport[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_ss_in_comp_desc,
	NULL,
};

/* High-Speed Support */

static struct usb_endpoint_descriptor hidg_hs_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_endpoint_descriptor hidg_hs_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 4, /* FIXME: Add this field in the
				      * HID gadget configuration?
				      * (struct hidg_func_descriptor)
				      */
};

static struct usb_descriptor_header *hidg_hs_descriptors_intout[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_hs_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_hs_out_ep_desc,
	NULL,
};

static struct usb_descriptor_header *hidg_hs_descriptors_ssreport[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_hs_in_ep_desc,
	NULL,
};

/* Full-Speed Support */

static struct usb_endpoint_descriptor hidg_fs_in_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_IN,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 10, /* FIXME: Add this field in the
				       * HID gadget configuration?
				       * (struct hidg_func_descriptor)
				       */
};

static struct usb_endpoint_descriptor hidg_fs_out_ep_desc = {
	.bLength		= USB_DT_ENDPOINT_SIZE,
	.bDescriptorType	= USB_DT_ENDPOINT,
	.bEndpointAddress	= USB_DIR_OUT,
	.bmAttributes		= USB_ENDPOINT_XFER_INT,
	/*.wMaxPacketSize	= DYNAMIC */
	.bInterval		= 10, /* FIXME: Add this field in the
				       * HID gadget configuration?
				       * (struct hidg_func_descriptor)
				       */
};

static struct usb_descriptor_header *hidg_fs_descriptors_intout[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_fs_in_ep_desc,
	(struct usb_descriptor_header *)&hidg_fs_out_ep_desc,
	NULL,
};

static struct usb_descriptor_header *hidg_fs_descriptors_ssreport[] = {
	(struct usb_descriptor_header *)&hidg_interface_desc,
	(struct usb_descriptor_header *)&hidg_desc,
	(struct usb_descriptor_header *)&hidg_fs_in_ep_desc,
	NULL,
};

/*-------------------------------------------------------------------------*/
/*                                 Strings                                 */

#define CT_FUNC_HID_IDX	0

static struct usb_string ct_func_string_defs[] = {
	[CT_FUNC_HID_IDX].s	= "HID Interface",
	{},			/* end of list */
};

static struct usb_gadget_strings ct_func_string_table = {
	.language	= 0x0409,	/* en-US */
	.strings	= ct_func_string_defs,
};

static struct usb_gadget_strings *ct_func_strings[] = {
	&ct_func_string_table,
	NULL,
};

/*-------------------------------------------------------------------------*/
/*                              Char Device                                */

static ssize_t f_hidg_intout_read(struct file *file, char __user *buffer,
				  size_t count, loff_t *ptr)
{
	struct f_hidg *hidg = file->private_data;
	struct f_hidg_req_list *list;
	struct usb_request *req;
	unsigned long flags;
	int ret;

	if (!count)
		return 0;

	spin_lock_irqsave(&hidg->read_spinlock, flags);

#define READ_COND_INTOUT (!list_empty(&hidg->completed_out_req))

	/* wait for at least one buffer to complete */
	while (!READ_COND_INTOUT) {
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible(hidg->read_queue, READ_COND_INTOUT))
			return -ERESTARTSYS;

		spin_lock_irqsave(&hidg->read_spinlock, flags);
	}

	/* pick the first one */
	list = list_first_entry(&hidg->completed_out_req,
				struct f_hidg_req_list, list);

	/*
	 * Remove this from list to protect it from beign free()
	 * while host disables our function
	 */
	list_del(&list->list);

	req = list->req;
	count = min_t(unsigned int, count, req->actual - list->pos);
	spin_unlock_irqrestore(&hidg->read_spinlock, flags);

	/* copy to user outside spinlock */
	count -= copy_to_user(buffer, req->buf + list->pos, count);
	list->pos += count;

	/*
	 * if this request is completely handled and transfered to
	 * userspace, remove its entry from the list and requeue it
	 * again. Otherwise, we will revisit it again upon the next
	 * call, taking into account its current read position.
	 */
	if (list->pos == req->actual) {
		kfree(list);

		req->length = hidg->report_length;
		ret = usb_ep_queue(hidg->out_ep, req, GFP_KERNEL);
		if (ret < 0) {
			free_ep_req(hidg->out_ep, req);
			return ret;
		}
	} else {
		spin_lock_irqsave(&hidg->read_spinlock, flags);
		list_add(&list->list, &hidg->completed_out_req);
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);

		wake_up(&hidg->read_queue);
	}

	return count;
}

#define READ_COND_SSREPORT (hidg->set_report_buf != NULL)

static ssize_t f_hidg_ssreport_read(struct file *file, char __user *buffer,
				    size_t count, loff_t *ptr)
{
	struct f_hidg *hidg = file->private_data;
	char *tmp_buf = NULL;
	unsigned long flags;

	if (!count)
		return 0;

	spin_lock_irqsave(&hidg->read_spinlock, flags);

	while (!READ_COND_SSREPORT) {
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible(hidg->read_queue, READ_COND_SSREPORT))
			return -ERESTARTSYS;

		spin_lock_irqsave(&hidg->read_spinlock, flags);
	}

	count = min_t(unsigned int, count, hidg->set_report_length);
	tmp_buf = hidg->set_report_buf;
	hidg->set_report_buf = NULL;

	spin_unlock_irqrestore(&hidg->read_spinlock, flags);

	if (tmp_buf != NULL) {
		count -= copy_to_user(buffer, tmp_buf, count);
		kfree(tmp_buf);
	} else {
		count = -ENOMEM;
	}

	wake_up(&hidg->read_queue);

	return count;
}

/* NaoYun Auth patch: 从质询队列取一条 Feature Report 给用户态（非阻塞）。
 * 返回 >0 已拷贝字节数；0 无质询；<0 用户缓冲过小 */
static ssize_t f_hidg_feat_read(struct f_hidg *hidg, char __user *buffer,
				size_t count)
{
	struct f_hidg_feat *feat;
	unsigned long flags;
	ssize_t ret;

	spin_lock_irqsave(&hidg->feat->lock, flags);
	if (list_empty(&hidg->feat->queue)) {
		spin_unlock_irqrestore(&hidg->feat->lock, flags);
		return 0;
	}
	feat = list_first_entry(&hidg->feat->queue, struct f_hidg_feat, list);
	if (count < feat->len) {
		spin_unlock_irqrestore(&hidg->feat->lock, flags);
		return -EINVAL;
	}
	list_del(&feat->list);
	spin_unlock_irqrestore(&hidg->feat->lock, flags);

	ret = feat->len - copy_to_user(buffer, feat->buf, feat->len);
	kfree(feat->buf);
	kfree(feat);
	return ret;
}

static ssize_t f_hidg_read(struct file *file, char __user *buffer,
			   size_t count, loff_t *ptr)
{
	struct f_hidg *hidg = file->private_data;
	ssize_t ret;

	if (!count)
		return 0;

	/* NaoYun Auth patch: Feature 质询优先于普通报文。
	 * use_out_ep 模式下质询不进 OUT 读队列，必须在此循环等待，
	 * 否则落入 intout 路径后非阻塞标志丢失，中继永远读不到质询 */
	if (hidg->use_out_ep) {
		while (1) {
			ret = f_hidg_feat_read(hidg, buffer, count);
			if (ret != 0)
				return ret;
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;
			if (wait_event_interruptible(hidg->read_queue,
					!list_empty(&hidg->feat->queue)))
				return -ERESTARTSYS;
		}
	}

	/* 非 use_out_ep（ssreport）模式：质询与 SET_REPORT 报文共用读队列，
	 * 先取质询，取不到再走原路径 */
	ret = f_hidg_feat_read(hidg, buffer, count);
	if (ret != 0)
		return ret;

	return f_hidg_ssreport_read(file, buffer, count, ptr);
}

static void f_hidg_req_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_hidg *hidg = (struct f_hidg *)ep->driver_data;
	unsigned long flags;

	if (req->status != 0) {
		ERROR(hidg->func.config->cdev,
			"End Point Request ERROR: %d\n", req->status);
	}

	spin_lock_irqsave(&hidg->write_spinlock, flags);
	hidg->write_pending = 0;
	spin_unlock_irqrestore(&hidg->write_spinlock, flags);
	wake_up(&hidg->write_queue);
}

/*
 * NaoYun Auth patch v4：载荷取入统一入口。
 *
 * 为什么要这一层（本机实测，不是猜）：5.15.145-conaco66 是去掉 set_fs 的 ARM64，
 * 内核线程拿不到用户地址空间——access_ok(内核指针)=0、直接调 .write 传内核指针得 -14(-EFAULT)、
 * kernel_write() 得 -22(-EINVAL)（它只走 .write_iter，而上游 f_hid 没有）。
 * 于是内核态写者（naoyun_motion 的出帧节拍）在这台盒上没有任何入口。
 * 补 .write_iter 是唯一不动用户态链路的做法：VFS 的 __vfs_write 优先 .write，
 * 现役用户态写者（svc-hid 的 /dev/hidgN、auth 中继的 Feature 应答）走的仍是原函数，逐字节不变。
 */
static int hidg_payload_fetch(void *dst, const char __user *src, size_t len,
			      bool from_kernel)
{
	if (from_kernel) {
		memcpy(dst, (const void __force *)src, len);
		return 0;
	}
	return copy_from_user(dst, src, len) ? -EFAULT : 0;
}

static ssize_t __f_hidg_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *offp, bool from_kernel)
{
	struct f_hidg *hidg  = file->private_data;
	struct usb_request *req;
	unsigned long flags;
	ssize_t status = -ENOMEM;

	/* NaoYun Auth patch: Feature ID 的写入为 Feature 应答（校准/固件/签名等），
	 * 存入对应 ID 槽供主机 GET_REPORT 读取，不走中断 IN 端点 */
	if (count >= 1 && count <= sizeof(hidg->feat->resp[0])) {
		u8 hdr;

		if (hidg_payload_fetch(&hdr, buffer, 1, from_kernel))
			return -EFAULT;
		if (hidg_feat_id(hdr)) {
			if (hidg_payload_fetch(hidg->feat->resp[hdr], buffer,
					       count, from_kernel))
				return -EFAULT;
			spin_lock_irqsave(&hidg->feat->lock, flags);
			hidg->feat->resp_len[hdr] = count;
			spin_unlock_irqrestore(&hidg->feat->lock, flags);
			pr_info_ratelimited("hidg: feature response staged id=0x%02x len=%zu\n",
					    hdr, count);
			return count;
		}
	}

	spin_lock_irqsave(&hidg->write_spinlock, flags);

	if (!hidg->req) {
		spin_unlock_irqrestore(&hidg->write_spinlock, flags);
		return -ESHUTDOWN;
	}

#define WRITE_COND (!hidg->write_pending)
try_again:
	/* write queue */
	while (!WRITE_COND) {
		spin_unlock_irqrestore(&hidg->write_spinlock, flags);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		if (wait_event_interruptible_exclusive(
				hidg->write_queue, WRITE_COND))
			return -ERESTARTSYS;

		spin_lock_irqsave(&hidg->write_spinlock, flags);
	}

	hidg->write_pending = 1;
	req = hidg->req;
	count  = min_t(unsigned, count, hidg->report_length);

	spin_unlock_irqrestore(&hidg->write_spinlock, flags);

	if (!req) {
		ERROR(hidg->func.config->cdev, "hidg->req is NULL\n");
		status = -ESHUTDOWN;
		goto release_write_pending;
	}

	status = hidg_payload_fetch(req->buf, buffer, count, from_kernel);
	if (status != 0) {
		ERROR(hidg->func.config->cdev,
			"payload fetch error\n");
		status = -EINVAL;
		goto release_write_pending;
	}

	spin_lock_irqsave(&hidg->write_spinlock, flags);

	/* when our function has been disabled by host */
	if (!hidg->req) {
		free_ep_req(hidg->in_ep, req);
		/*
		 * TODO
		 * Should we fail with error here?
		 */
		goto try_again;
	}

	req->status   = 0;
	req->zero     = 0;
	req->length   = count;
	req->complete = f_hidg_req_complete;
	req->context  = hidg;

	spin_unlock_irqrestore(&hidg->write_spinlock, flags);

	if (!hidg->in_ep->enabled) {
		ERROR(hidg->func.config->cdev, "in_ep is disabled\n");
		status = -ESHUTDOWN;
		goto release_write_pending;
	}

	status = usb_ep_queue(hidg->in_ep, req, GFP_ATOMIC);
	if (status < 0)
		goto release_write_pending;
	else
		status = count;

	return status;
release_write_pending:
	spin_lock_irqsave(&hidg->write_spinlock, flags);
	hidg->write_pending = 0;
	spin_unlock_irqrestore(&hidg->write_spinlock, flags);

	wake_up(&hidg->write_queue);

	return status;
}

static ssize_t f_hidg_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *offp)
{
	/* 用户态写者：路径与 v3 完全一致（.write 仍是 VFS 首选） */
	return __f_hidg_write(file, buffer, count, offp, false);
}

/*
 * 内核态写者入口：kernel_write() → vfs_iter_write() → 这里。
 * 迭代器先线性化到栈缓冲——鼠标/键盘报文 ≤64 字节，超过 HIDG_KW_MAX 直接拒收：
 * 半帧比失败更坏（主机会把残缺报文当成一次真实移动）。
 */
#define HIDG_KW_MAX 512
static ssize_t f_hidg_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file	*file = iocb->ki_filp;
	size_t		 count = iov_iter_count(from);
	u8		 kbuf[HIDG_KW_MAX];

	if (!count)
		return 0;
	if (count > sizeof(kbuf))
		return -EINVAL;
	if (copy_from_iter(kbuf, count, from) != count)
		return -EFAULT;
	return __f_hidg_write(file, (void __force __user *)kbuf, count,
			      &iocb->ki_pos, true);
}

static __poll_t f_hidg_poll(struct file *file, poll_table *wait)
{
	struct f_hidg	*hidg  = file->private_data;
	unsigned long	flags;
	__poll_t	ret = 0;

	poll_wait(file, &hidg->read_queue, wait);
	poll_wait(file, &hidg->write_queue, wait);

	if (WRITE_COND)
		ret |= EPOLLOUT | EPOLLWRNORM;

	if (hidg->use_out_ep) {
		/* NaoYun Auth patch v2: Feature 质询队列可读也必须上报。
		 * Go 运行时对字符设备用 非阻塞+epoll 读：v1 漏报导致 epoll
		 * 永远等不到 EPOLLIN，用户态中继 goroutine 死等，质询永不被消费 */
		bool feat_ready;

		spin_lock_irqsave(&hidg->feat->lock, flags);
		feat_ready = !list_empty(&hidg->feat->queue);
		spin_unlock_irqrestore(&hidg->feat->lock, flags);
		if (feat_ready)
			ret |= EPOLLIN | EPOLLRDNORM;
		if (READ_COND_INTOUT)
			ret |= EPOLLIN | EPOLLRDNORM;
	} else {
		if (READ_COND_SSREPORT)
			ret |= EPOLLIN | EPOLLRDNORM;
	}

	return ret;
}

#undef WRITE_COND
#undef READ_COND_SSREPORT
#undef READ_COND_INTOUT

static int f_hidg_release(struct inode *inode, struct file *fd)
{
	fd->private_data = NULL;
	return 0;
}

static int f_hidg_open(struct inode *inode, struct file *fd)
{
	struct f_hidg *hidg =
		container_of(inode->i_cdev, struct f_hidg, cdev);

	fd->private_data = hidg;

	return 0;
}

/*-------------------------------------------------------------------------*/
/*                                usb_function                             */

static inline struct usb_request *hidg_alloc_ep_req(struct usb_ep *ep,
						    unsigned length)
{
	return alloc_ep_req(ep, length);
}

static void hidg_intout_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_hidg *hidg = (struct f_hidg *) req->context;
	struct usb_composite_dev *cdev = hidg->func.config->cdev;
	struct f_hidg_req_list *req_list;
	unsigned long flags;

	switch (req->status) {
	case 0:
		/* NaoYun Auth patch: 0x80/≥0xF0 为质询/Feature 报文（PS5 实测质询 0x80），
		 * 旁路到质询队列供用户态中继，不进普通读队列 */
		if (req->actual > 0 && hidg_feat_relay_id(((u8 *)req->buf)[0])) {
			hidg_feat_queue(hidg, req->buf, req->actual);
			req->length = hidg->report_length;
			if (usb_ep_queue(ep, req, GFP_ATOMIC) < 0)
				free_ep_req(ep, req);
			return;
		}

		req_list = kzalloc(sizeof(*req_list), GFP_ATOMIC);
		if (!req_list) {
			ERROR(cdev, "Unable to allocate mem for req_list\n");
			goto free_req;
		}

		req_list->req = req;

		spin_lock_irqsave(&hidg->read_spinlock, flags);
		list_add_tail(&req_list->list, &hidg->completed_out_req);
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);

		wake_up(&hidg->read_queue);
		break;
	default:
		ERROR(cdev, "Set report failed %d\n", req->status);
		fallthrough;
	case -ECONNABORTED:		/* hardware forced ep reset */
	case -ECONNRESET:		/* request dequeued */
	case -ESHUTDOWN:		/* disconnect from host */
free_req:
		free_ep_req(ep, req);
		return;
	}
}

static void hidg_ssreport_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_hidg *hidg = (struct f_hidg *)req->context;
	struct usb_composite_dev *cdev = hidg->func.config->cdev;
	char *new_buf = NULL;
	unsigned long flags;

	/* NaoYun Auth debug: 入口无条件记录，定位 PS5 0xF0 质询数据相位的下落 */
	pr_info("hidg: ssreport_complete status=%d actual=%d id=0x%02x\n",
		req->status, req->actual,
		(req->actual > 0 && req->buf) ? ((u8 *)req->buf)[0] : 0);

	if (req->status != 0 || req->buf == NULL || req->actual == 0) {
		ERROR(cdev,
		      "%s FAILED: status=%d, buf=%p, actual=%d\n",
		      __func__, req->status, req->buf, req->actual);
		return;
	}

	spin_lock_irqsave(&hidg->read_spinlock, flags);

	new_buf = krealloc(hidg->set_report_buf, req->actual, GFP_ATOMIC);
	if (new_buf == NULL) {
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);
		return;
	}
	hidg->set_report_buf = new_buf;

	hidg->set_report_length = req->actual;
	memcpy(hidg->set_report_buf, req->buf, req->actual);

	spin_unlock_irqrestore(&hidg->read_spinlock, flags);

	/* NaoYun Auth patch: SET_REPORT 控制通道下发的质询报文同样入队 */
	if (req->actual > 0 && hidg_feat_relay_id(((u8 *)req->buf)[0]))
		hidg_feat_queue(hidg, req->buf, req->actual);

	wake_up(&hidg->read_queue);
}

static int hidg_setup(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl)
{
	struct f_hidg			*hidg = func_to_hidg(f);
	struct usb_composite_dev	*cdev = f->config->cdev;
	struct usb_request		*req  = cdev->req;
	int status = 0;
	__u16 value, length;

	value	= __le16_to_cpu(ctrl->wValue);
	length	= __le16_to_cpu(ctrl->wLength);

	VDBG(cdev,
	     "%s crtl_request : bRequestType:0x%x bRequest:0x%x Value:0x%x\n",
	     __func__, ctrl->bRequestType, ctrl->bRequest, value);

	/* NaoYun Auth debug: 无条件记录全部控制请求，供 PS5 交互取证 */
	pr_info_ratelimited("hidg setup: type=0x%02x req=0x%02x val=0x%04x idx=0x%04x len=%u\n",
			    ctrl->bRequestType, ctrl->bRequest, value,
			    __le16_to_cpu(ctrl->wIndex), length);

	switch ((ctrl->bRequestType << 8) | ctrl->bRequest) {
	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_GET_REPORT):
		VDBG(cdev, "get_report\n");

		/* NaoYun Auth patch v2: Feature 类型 GET_REPORT（wValue 高字节 == 0x03）
		 * 返回对应 Report ID 槽中用户态暂存的真手柄数据；未预置的维持原版空报文行为 */
		if ((value >> 8) == 0x03) {
			u8 fid = value & 0xff;
			unsigned long fflags;

			spin_lock_irqsave(&hidg->feat->lock, fflags);
			if (hidg->feat->resp_len[fid] > 0) {
				length = min_t(unsigned, length, hidg->feat->resp_len[fid]);
				memcpy(req->buf, hidg->feat->resp[fid], length);
				/* NaoYun Auth patch v3: 命中即清零 stall 计数 */
				hidg->feat->stall_count[fid] = 0;
				spin_unlock_irqrestore(&hidg->feat->lock, fflags);
				/* NaoYun Auth patch v2: 命中实锤日志，证明主机读到了预置真数据 */
				pr_info_ratelimited("hidg: GET_REPORT id=0x%02x HIT staged, return %u bytes\n",
						    fid, length);
				goto respond;
			}

			/* NaoYun Auth patch v3: 关键 Auth ID (0x81) 响应未到时 STALL 等重试，
			 * 给源端求解+中继争取时间；stall_count 超限降级回零防死循环 */
			if (hidg_feat_stall_id(fid) &&
			    hidg->feat->stall_count[fid] < HIDG_STALL_MAX) {
				hidg->feat->stall_count[fid]++;
				spin_unlock_irqrestore(&hidg->feat->lock, fflags);
				pr_info("hidg: GET_REPORT id=0x%02x STALL #%u, waiting for response\n",
					fid, hidg->feat->stall_count[fid]);
				goto stall;
			}

			spin_unlock_irqrestore(&hidg->feat->lock, fflags);
			/* NaoYun Auth patch v3: 超限或非关键 ID 降级回全零 */
			pr_info_ratelimited("hidg: GET_REPORT id=0x%02x MISS (stall=%u), return zeros\n",
					    fid, hidg->feat->stall_count[fid]);
		}

		/* send an empty report */
		length = min_t(unsigned, length, hidg->report_length);
		memset(req->buf, 0x0, length);

		goto respond;
		break;

	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_GET_PROTOCOL):
		VDBG(cdev, "get_protocol\n");
		length = min_t(unsigned int, length, 1);
		((u8 *) req->buf)[0] = hidg->protocol;
		goto respond;
		break;

	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_GET_IDLE):
		VDBG(cdev, "get_idle\n");
		length = min_t(unsigned int, length, 1);
		((u8 *) req->buf)[0] = hidg->idle;
		goto respond;
		break;

	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_SET_REPORT):
		VDBG(cdev, "set_report | wLength=%d\n", ctrl->wLength);
		/* NaoYun Auth patch: Feature 类型 SET_REPORT（wValue 高字节 == 0x03，
		 * PS5 质询 0xF0）即使在 use_out_ep 模式也必须接收并入队；
		 * 普通 OUTPUT 报文维持原版 stall 行为 */
		if (hidg->use_out_ep && (value >> 8) != 0x03)
			goto stall;
		req->complete = hidg_ssreport_complete;
		req->context  = hidg;
		goto respond;
		break;

	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_SET_PROTOCOL):
		VDBG(cdev, "set_protocol\n");
		if (value > HID_REPORT_PROTOCOL)
			goto stall;
		length = 0;
		/*
		 * We assume that programs implementing the Boot protocol
		 * are also compatible with the Report Protocol
		 */
		if (hidg->bInterfaceSubClass == USB_INTERFACE_SUBCLASS_BOOT) {
			hidg->protocol = value;
			goto respond;
		}
		goto stall;
		break;

	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8
		  | HID_REQ_SET_IDLE):
		VDBG(cdev, "set_idle\n");
		length = 0;
		hidg->idle = value >> 8;
		goto respond;
		break;

	case ((USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE) << 8
		  | USB_REQ_GET_DESCRIPTOR):
		switch (value >> 8) {
		case HID_DT_HID:
		{
			struct hid_descriptor hidg_desc_copy = hidg_desc;

			VDBG(cdev, "USB_REQ_GET_DESCRIPTOR: HID\n");
			hidg_desc_copy.desc[0].bDescriptorType = HID_DT_REPORT;
			hidg_desc_copy.desc[0].wDescriptorLength =
				cpu_to_le16(hidg->report_desc_length);

			length = min_t(unsigned short, length,
						   hidg_desc_copy.bLength);
			memcpy(req->buf, &hidg_desc_copy, length);
			goto respond;
			break;
		}
		case HID_DT_REPORT:
			VDBG(cdev, "USB_REQ_GET_DESCRIPTOR: REPORT\n");
			length = min_t(unsigned short, length,
						   hidg->report_desc_length);
			memcpy(req->buf, hidg->report_desc, length);
			goto respond;
			break;

		default:
			VDBG(cdev, "Unknown descriptor request 0x%x\n",
				 value >> 8);
			goto stall;
			break;
		}
		break;

	default:
		VDBG(cdev, "Unknown request 0x%x\n",
			 ctrl->bRequest);
		goto stall;
		break;
	}

stall:
	return -EOPNOTSUPP;

respond:
	req->zero = 0;
	req->length = length;
	status = usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
	if (status < 0)
		ERROR(cdev, "usb_ep_queue error on ep0 %d\n", value);
	return status;
}

static void hidg_disable(struct usb_function *f)
{
	struct f_hidg *hidg = func_to_hidg(f);
	struct f_hidg_req_list *list, *next;
	unsigned long flags;

	usb_ep_disable(hidg->in_ep);

	if (hidg->out_ep) {
		usb_ep_disable(hidg->out_ep);

		spin_lock_irqsave(&hidg->read_spinlock, flags);
		list_for_each_entry_safe(list, next, &hidg->completed_out_req, list) {
			free_ep_req(hidg->out_ep, list->req);
			list_del(&list->list);
			kfree(list);
		}
		spin_unlock_irqrestore(&hidg->read_spinlock, flags);
	}

	/* NaoYun Auth patch: 清空质询队列防泄漏；
	 * v2: feat_resp 暂存槽故意不清——PS5 枚举后 700ms 内就读 Feature，
	 * 预置数据必须跨软拔插(disable/enable)存活，仅重建 function 时初始化 */
	{
		struct f_hidg_feat *feat, *tmp;

		spin_lock_irqsave(&hidg->feat->lock, flags);
		list_for_each_entry_safe(feat, tmp, &hidg->feat->queue, list) {
			list_del(&feat->list);
			kfree(feat->buf);
			kfree(feat);
		}
		spin_unlock_irqrestore(&hidg->feat->lock, flags);
	}

	spin_lock_irqsave(&hidg->write_spinlock, flags);
	if (!hidg->write_pending) {
		free_ep_req(hidg->in_ep, hidg->req);
		hidg->write_pending = 1;
	}

	hidg->req = NULL;
	spin_unlock_irqrestore(&hidg->write_spinlock, flags);
}

static int hidg_set_alt(struct usb_function *f, unsigned intf, unsigned alt)
{
	struct usb_composite_dev		*cdev = f->config->cdev;
	struct f_hidg				*hidg = func_to_hidg(f);
	struct usb_request			*req_in = NULL;
	unsigned long				flags;
	int i, status = 0;

	VDBG(cdev, "hidg_set_alt intf:%d alt:%d\n", intf, alt);

	if (hidg->in_ep != NULL) {
		/* restart endpoint */
		usb_ep_disable(hidg->in_ep);

		status = config_ep_by_speed(f->config->cdev->gadget, f,
					    hidg->in_ep);
		if (status) {
			ERROR(cdev, "config_ep_by_speed FAILED!\n");
			goto fail;
		}
		status = usb_ep_enable(hidg->in_ep);
		if (status < 0) {
			ERROR(cdev, "Enable IN endpoint FAILED!\n");
			goto fail;
		}
		hidg->in_ep->driver_data = hidg;

		req_in = hidg_alloc_ep_req(hidg->in_ep, hidg->report_length);
		if (!req_in) {
			status = -ENOMEM;
			goto disable_ep_in;
		}
	}

	if (hidg->use_out_ep && hidg->out_ep != NULL) {
		/* restart endpoint */
		usb_ep_disable(hidg->out_ep);

		status = config_ep_by_speed(f->config->cdev->gadget, f,
					    hidg->out_ep);
		if (status) {
			ERROR(cdev, "config_ep_by_speed FAILED!\n");
			goto free_req_in;
		}
		status = usb_ep_enable(hidg->out_ep);
		if (status < 0) {
			ERROR(cdev, "Enable OUT endpoint FAILED!\n");
			goto free_req_in;
		}
		hidg->out_ep->driver_data = hidg;

		/*
		 * allocate a bunch of read buffers and queue them all at once.
		 */
		for (i = 0; i < hidg->qlen && status == 0; i++) {
			struct usb_request *req =
					hidg_alloc_ep_req(hidg->out_ep,
							  hidg->report_length);
			if (req) {
				req->complete = hidg_intout_complete;
				req->context  = hidg;
				status = usb_ep_queue(hidg->out_ep, req,
						      GFP_ATOMIC);
				if (status) {
					ERROR(cdev, "%s queue req --> %d\n",
						hidg->out_ep->name, status);
					free_ep_req(hidg->out_ep, req);
				}
			} else {
				status = -ENOMEM;
				goto disable_out_ep;
			}
		}
	}

	if (hidg->in_ep != NULL) {
		spin_lock_irqsave(&hidg->write_spinlock, flags);
		hidg->req = req_in;
		hidg->write_pending = 0;
		spin_unlock_irqrestore(&hidg->write_spinlock, flags);

		wake_up(&hidg->write_queue);
	}
	return 0;
disable_out_ep:
	if (hidg->out_ep)
		usb_ep_disable(hidg->out_ep);
free_req_in:
	if (req_in)
		free_ep_req(hidg->in_ep, req_in);

disable_ep_in:
	if (hidg->in_ep)
		usb_ep_disable(hidg->in_ep);

fail:
	return status;
}

static const struct file_operations f_hidg_fops = {
	.owner		= THIS_MODULE,
	.open		= f_hidg_open,
	.release	= f_hidg_release,
	.write		= f_hidg_write,
	/* NaoYun Auth patch v4: 内核态写者唯一入口（naoyun_motion 出帧）。
	 * 用户态 write() 不走这里（VFS 优先 .write），现役链路零变化 */
	.write_iter	= f_hidg_write_iter,
	.read		= f_hidg_read,
	.poll		= f_hidg_poll,
	.llseek		= noop_llseek,
};

static int hidg_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_ep		*ep;
	struct f_hidg		*hidg = func_to_hidg(f);
	struct usb_string	*us;
	int			status;

	/* maybe allocate device-global string IDs, and patch descriptors */
	us = usb_gstrings_attach(c->cdev, ct_func_strings,
				 ARRAY_SIZE(ct_func_string_defs));
	if (IS_ERR(us))
		return PTR_ERR(us);
	hidg_interface_desc.iInterface = us[CT_FUNC_HID_IDX].id;

	/* allocate instance-specific interface IDs, and patch descriptors */
	status = usb_interface_id(c, f);
	if (status < 0)
		goto fail;
	hidg_interface_desc.bInterfaceNumber = status;

	/* allocate instance-specific endpoints */
	status = -ENODEV;
	ep = usb_ep_autoconfig(c->cdev->gadget, &hidg_fs_in_ep_desc);
	if (!ep)
		goto fail;
	hidg->in_ep = ep;

	hidg->out_ep = NULL;
	if (hidg->use_out_ep) {
		ep = usb_ep_autoconfig(c->cdev->gadget, &hidg_fs_out_ep_desc);
		if (!ep)
			goto fail;
		hidg->out_ep = ep;
	}

	/* used only if use_out_ep == 1 */
	hidg->set_report_buf = NULL;

	/* set descriptor dynamic values */
	hidg_interface_desc.bInterfaceSubClass = hidg->bInterfaceSubClass;
	hidg_interface_desc.bInterfaceProtocol = hidg->bInterfaceProtocol;
	hidg_interface_desc.bNumEndpoints = hidg->use_out_ep ? 2 : 1;
	hidg->protocol = HID_REPORT_PROTOCOL;
	hidg->idle = 1;
	hidg_ss_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	hidg_ss_in_comp_desc.wBytesPerInterval =
				cpu_to_le16(hidg->report_length);
	hidg_hs_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	hidg_fs_in_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	hidg_ss_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	hidg_ss_out_comp_desc.wBytesPerInterval =
				cpu_to_le16(hidg->report_length);
	hidg_hs_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	hidg_fs_out_ep_desc.wMaxPacketSize = cpu_to_le16(hidg->report_length);
	/*
	 * We can use hidg_desc struct here but we should not relay
	 * that its content won't change after returning from this function.
	 */
	hidg_desc.desc[0].bDescriptorType = HID_DT_REPORT;
	hidg_desc.desc[0].wDescriptorLength =
		cpu_to_le16(hidg->report_desc_length);

	hidg_hs_in_ep_desc.bEndpointAddress =
		hidg_fs_in_ep_desc.bEndpointAddress;
	hidg_hs_out_ep_desc.bEndpointAddress =
		hidg_fs_out_ep_desc.bEndpointAddress;

	hidg_ss_in_ep_desc.bEndpointAddress =
		hidg_fs_in_ep_desc.bEndpointAddress;
	hidg_ss_out_ep_desc.bEndpointAddress =
		hidg_fs_out_ep_desc.bEndpointAddress;

	if (hidg->use_out_ep)
		status = usb_assign_descriptors(f,
			hidg_fs_descriptors_intout,
			hidg_hs_descriptors_intout,
			hidg_ss_descriptors_intout,
			hidg_ss_descriptors_intout);
	else
		status = usb_assign_descriptors(f,
			hidg_fs_descriptors_ssreport,
			hidg_hs_descriptors_ssreport,
			hidg_ss_descriptors_ssreport,
			hidg_ss_descriptors_ssreport);

	if (status)
		goto fail;

	spin_lock_init(&hidg->write_spinlock);
	hidg->write_pending = 1;
	hidg->req = NULL;
	spin_lock_init(&hidg->read_spinlock);
	init_waitqueue_head(&hidg->write_queue);
	init_waitqueue_head(&hidg->read_queue);
	INIT_LIST_HEAD(&hidg->completed_out_req);

	/* create char device */
	cdev_init(&hidg->cdev, &f_hidg_fops);
	status = cdev_device_add(&hidg->cdev, &hidg->dev);
	if (status)
		goto fail_free_descs;

	return 0;
fail_free_descs:
	usb_free_all_descriptors(f);
fail:
	ERROR(f->config->cdev, "hidg_bind FAILED\n");
	if (hidg->req != NULL)
		free_ep_req(hidg->in_ep, hidg->req);

	return status;
}

static inline int hidg_get_minor(void)
{
	int ret;

	ret = ida_simple_get(&hidg_ida, 0, 0, GFP_KERNEL);
	if (ret >= HIDG_MINORS) {
		ida_simple_remove(&hidg_ida, ret);
		ret = -ENODEV;
	}

	return ret;
}

static inline struct f_hid_opts *to_f_hid_opts(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_hid_opts,
			    func_inst.group);
}

static void hid_attr_release(struct config_item *item)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);

	usb_put_function_instance(&opts->func_inst);
}

static struct configfs_item_operations hidg_item_ops = {
	.release	= hid_attr_release,
};

#define F_HID_OPT(name, prec, limit)					\
static ssize_t f_hid_opts_##name##_show(struct config_item *item, char *page)\
{									\
	struct f_hid_opts *opts = to_f_hid_opts(item);			\
	int result;							\
									\
	mutex_lock(&opts->lock);					\
	result = sprintf(page, "%d\n", opts->name);			\
	mutex_unlock(&opts->lock);					\
									\
	return result;							\
}									\
									\
static ssize_t f_hid_opts_##name##_store(struct config_item *item,	\
					 const char *page, size_t len)	\
{									\
	struct f_hid_opts *opts = to_f_hid_opts(item);			\
	int ret;							\
	u##prec num;							\
									\
	mutex_lock(&opts->lock);					\
	if (opts->refcnt) {						\
		ret = -EBUSY;						\
		goto end;						\
	}								\
									\
	ret = kstrtou##prec(page, 0, &num);				\
	if (ret)							\
		goto end;						\
									\
	if (num > limit) {						\
		ret = -EINVAL;						\
		goto end;						\
	}								\
	opts->name = num;						\
	ret = len;							\
									\
end:									\
	mutex_unlock(&opts->lock);					\
	return ret;							\
}									\
									\
CONFIGFS_ATTR(f_hid_opts_, name)

F_HID_OPT(subclass, 8, 255);
F_HID_OPT(protocol, 8, 255);
F_HID_OPT(no_out_endpoint, 8, 1);
F_HID_OPT(report_length, 16, 65535);

static ssize_t f_hid_opts_report_desc_show(struct config_item *item, char *page)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);
	int result;

	mutex_lock(&opts->lock);
	result = opts->report_desc_length;
	memcpy(page, opts->report_desc, opts->report_desc_length);
	mutex_unlock(&opts->lock);

	return result;
}

static ssize_t f_hid_opts_report_desc_store(struct config_item *item,
					    const char *page, size_t len)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);
	int ret = -EBUSY;
	char *d;

	mutex_lock(&opts->lock);

	if (opts->refcnt)
		goto end;
	if (len > PAGE_SIZE) {
		ret = -ENOSPC;
		goto end;
	}
	d = kmemdup(page, len, GFP_KERNEL);
	if (!d) {
		ret = -ENOMEM;
		goto end;
	}
	kfree(opts->report_desc);
	opts->report_desc = d;
	opts->report_desc_length = len;
	opts->report_desc_alloc = true;
	ret = len;
end:
	mutex_unlock(&opts->lock);
	return ret;
}

CONFIGFS_ATTR(f_hid_opts_, report_desc);

static ssize_t f_hid_opts_dev_show(struct config_item *item, char *page)
{
	struct f_hid_opts *opts = to_f_hid_opts(item);

	return sprintf(page, "%d:%d\n", major, opts->minor);
}

CONFIGFS_ATTR_RO(f_hid_opts_, dev);

static struct configfs_attribute *hid_attrs[] = {
	&f_hid_opts_attr_subclass,
	&f_hid_opts_attr_protocol,
	&f_hid_opts_attr_no_out_endpoint,
	&f_hid_opts_attr_report_length,
	&f_hid_opts_attr_report_desc,
	&f_hid_opts_attr_dev,
	NULL,
};

static const struct config_item_type hid_func_type = {
	.ct_item_ops	= &hidg_item_ops,
	.ct_attrs	= hid_attrs,
	.ct_owner	= THIS_MODULE,
};

static inline void hidg_put_minor(int minor)
{
	ida_simple_remove(&hidg_ida, minor);
}

static void hidg_free_inst(struct usb_function_instance *f)
{
	struct f_hid_opts *opts;

	opts = container_of(f, struct f_hid_opts, func_inst);

	mutex_lock(&hidg_ida_lock);

	hidg_put_minor(opts->minor);
	if (ida_is_empty(&hidg_ida))
		ghid_cleanup();

	mutex_unlock(&hidg_ida_lock);

	if (opts->report_desc_alloc)
		kfree(opts->report_desc);

	/* NaoYun Auth patch v2: 释放质询队列与实例层持久暂存 */
	if (opts->feat) {
		struct f_hidg_feat *feat, *tmp;
		unsigned long flags;

		spin_lock_irqsave(&opts->feat->lock, flags);
		list_for_each_entry_safe(feat, tmp, &opts->feat->queue, list) {
			list_del(&feat->list);
			kfree(feat->buf);
			kfree(feat);
		}
		spin_unlock_irqrestore(&opts->feat->lock, flags);
		kfree(opts->feat);
	}

	kfree(opts);
}

static struct usb_function_instance *hidg_alloc_inst(void)
{
	struct f_hid_opts *opts;
	struct usb_function_instance *ret;
	int status = 0;

	opts = kzalloc(sizeof(*opts), GFP_KERNEL);
	if (!opts)
		return ERR_PTR(-ENOMEM);
	mutex_init(&opts->lock);
	/* NaoYun Auth patch v2: 实例层持久暂存，只随 configfs 函数实例创建/销毁，
	 * 不随 UDC 重绑重建，预置的 Feature 应答才能真正跨软拔插存活 */
	opts->feat = kzalloc(sizeof(*opts->feat), GFP_KERNEL);
	if (!opts->feat) {
		kfree(opts);
		return ERR_PTR(-ENOMEM);
	}
	spin_lock_init(&opts->feat->lock);
	INIT_LIST_HEAD(&opts->feat->queue);
	opts->func_inst.free_func_inst = hidg_free_inst;
	ret = &opts->func_inst;

	mutex_lock(&hidg_ida_lock);

	if (ida_is_empty(&hidg_ida)) {
		status = ghid_setup(NULL, HIDG_MINORS);
		if (status)  {
			ret = ERR_PTR(status);
			kfree(opts->feat);
			kfree(opts);
			goto unlock;
		}
	}

	opts->minor = hidg_get_minor();
	if (opts->minor < 0) {
		ret = ERR_PTR(opts->minor);
		kfree(opts->feat);
		kfree(opts);
		if (ida_is_empty(&hidg_ida))
			ghid_cleanup();
		goto unlock;
	}
	config_group_init_type_name(&opts->func_inst.group, "", &hid_func_type);

unlock:
	mutex_unlock(&hidg_ida_lock);
	return ret;
}

static void hidg_free(struct usb_function *f)
{
	struct f_hidg *hidg;
	struct f_hid_opts *opts;

	hidg = func_to_hidg(f);
	opts = container_of(f->fi, struct f_hid_opts, func_inst);
	put_device(&hidg->dev);
	mutex_lock(&opts->lock);
	--opts->refcnt;
	mutex_unlock(&opts->lock);
}

static void hidg_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct f_hidg *hidg = func_to_hidg(f);

	cdev_device_del(&hidg->cdev, &hidg->dev);

	usb_free_all_descriptors(f);
}

static struct usb_function *hidg_alloc(struct usb_function_instance *fi)
{
	struct f_hidg *hidg;
	struct f_hid_opts *opts;
	int ret;

	/* allocate and initialize one new instance */
	hidg = kzalloc(sizeof(*hidg), GFP_KERNEL);
	if (!hidg)
		return ERR_PTR(-ENOMEM);

	opts = container_of(fi, struct f_hid_opts, func_inst);

	mutex_lock(&opts->lock);
	++opts->refcnt;

	device_initialize(&hidg->dev);
	hidg->dev.release = hidg_release;
	hidg->dev.class = hidg_class;
	hidg->dev.devt = MKDEV(major, opts->minor);
	ret = dev_set_name(&hidg->dev, "hidg%d", opts->minor);
	if (ret) {
		--opts->refcnt;
		mutex_unlock(&opts->lock);
		return ERR_PTR(ret);
	}

	hidg->bInterfaceSubClass = opts->subclass;
	hidg->bInterfaceProtocol = opts->protocol;
	hidg->report_length = opts->report_length;
	hidg->report_desc_length = opts->report_desc_length;
	if (opts->report_desc) {
		hidg->report_desc = kmemdup(opts->report_desc,
					    opts->report_desc_length,
					    GFP_KERNEL);
		if (!hidg->report_desc) {
			put_device(&hidg->dev);
			--opts->refcnt;
			mutex_unlock(&opts->lock);
			return ERR_PTR(-ENOMEM);
		}
	}
	hidg->use_out_ep = !opts->no_out_endpoint;
	/* NaoYun Auth patch v2: 接上实例层持久暂存（跨 UDC 重绑存活） */
	hidg->feat = opts->feat;

	mutex_unlock(&opts->lock);

	hidg->func.name    = "hid";
	hidg->func.bind    = hidg_bind;
	hidg->func.unbind  = hidg_unbind;
	hidg->func.set_alt = hidg_set_alt;
	hidg->func.disable = hidg_disable;
	hidg->func.setup   = hidg_setup;
	hidg->func.free_func = hidg_free;

	/* this could be made configurable at some point */
	hidg->qlen	   = 4;

	return &hidg->func;
}

DECLARE_USB_FUNCTION_INIT(hid, hidg_alloc_inst, hidg_alloc);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabien Chouteau");
/* NaoYun Auth patch: 身份指纹，agent 通过 /sys/module/usb_f_hid/version 检测是否补丁版，
 * 防止 guard/重启换回原版模块。改名/删除会导致模块自保失效
 * v4 = v3 全部能力 + .write_iter（内核态写者入口，鼠标出帧节拍 naoyun_motion 依赖它）；
 * 版本门是前缀判定（auth_relay.go: PatchedFHidVersionPrefix = "naoyun-auth-v"），升号不用改 Go */
MODULE_VERSION("naoyun-auth-v4");

int ghid_setup(struct usb_gadget *g, int count)
{
	int status;
	dev_t dev;

	hidg_class = class_create(THIS_MODULE, "hidg");
	if (IS_ERR(hidg_class)) {
		status = PTR_ERR(hidg_class);
		hidg_class = NULL;
		return status;
	}

	status = alloc_chrdev_region(&dev, 0, count, "hidg");
	if (status) {
		class_destroy(hidg_class);
		hidg_class = NULL;
		return status;
	}

	major = MAJOR(dev);
	minors = count;

	return 0;
}

void ghid_cleanup(void)
{
	if (major) {
		unregister_chrdev_region(MKDEV(major, 0), minors);
		major = minors = 0;
	}

	class_destroy(hidg_class);
	hidg_class = NULL;
}
