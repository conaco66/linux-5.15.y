/* SPDX-License-Identifier: GPL-2.0 */
/*
 * naoyun_motion.c — 盒端鼠标出帧的内核模块：真鼠标透传 + 惯性展开。
 *
 * 计划书：D:\aiwork\naoyun-saas\docs\plan-box-hid-mouse-service.md §二
 * 用户裁定（2026-10-13）原话：「需要增加一点惯性，避免网络延迟，不在用户态跑循环，
 * 改用内核模块跑动力学」「鼠标的输入肯定是要透传的啊」「这个是针对电脑的，不是ps5」
 *
 * 这个模块只管一件事：**出帧节拍**。它把"意图"（真鼠标的位移事件，或 3 期网络下发的脉冲）
 * 累进 pending，再按固定节拍展开成一帧帧 HID 报告写进 gadget 的 /dev/hidg1。
 * 网络抖动只决定"意图来得晚不晚"，不决定"帧出得稳不稳"——这就是要的惯性。
 *
 * ── 三条上下文纪律（写错会打挂整机，不是风格问题）─────────────────────
 * 1) input handler 的 ->event() 跑在中断/softirq 上下文：只准 spin_lock + 累加 + wake_up，
 *    不分配、不睡眠、不写文件。
 * 2) hrtimer 回调也是原子上下文，**不能**在里面 kernel_write：f_hidg_write 在没有空闲
 *    request 时会 wait_event 睡过去。所以节拍循环用 **kthread**（可睡眠）。
 *    ⚠ v1 在这儿踩过一个实测出来的坑：节拍等待用的是 `wait_event_interruptible_hrtimeout()`，
 *    而内核线程只要有**挂起信号**（被 block 也算 signal_pending），interruptible 系列就立刻回
 *    -ERESTARTSYS —— 实测 `/proc/<pid>/status` 的 voluntary_ctxt_switches **一秒都不增**、
 *    线程以 0.3~0.4 核空转，`tick_us` 改成 200ms 也一点不动速率。也就是说 v1 的"1ms 节拍"
 *    在真机上根本没生效：有 pending 时它是能发多快发多快。v2 起：**节拍用 usleep_range()
 *    （hrtimer 后端、不看信号脸色的定点睡）**，静止等待用不可中断的 `wait_event_timeout()`，
 *    新意图靠 push_intent 里的 wake_up 立刻叫醒（TASK_NORMAL 覆盖 UNINTERRUPTIBLE）。
 *    判据就是下面这条不变式：**发帧尝试次数/秒 ≈ 1e6/tick_us**，实测对拍在 §十二.7。
 * 3) /dev/hidg1 必须以 **O_NONBLOCK** 打开：主机（电脑）不来取帧时写会挂在写队列上，
 *    阻塞式会把 kthread 死锁在那儿，连带 rmmod 卡住。非阻塞下拿 -EAGAIN 就把 pending 补回去，
 *    下一拍再试——位移不丢，只是晚发。
 *
 * ── 守恒律（"惯性"不等于"丢位移"）───────────────────────────────────
 * 每帧只从 pending 扣真正写出去的那部分，写失败不扣；剩余小于 deadzone 时一次发完。
 * 所以指针最终落点与真鼠标完全一致，只是中途被平滑过。
 *
 * ⚠ **守恒律唯一的让路场景：根本没有输出目标**（2026-10-16 用户裁定，原话
 * 「电脑没连期间不攒 pending 直接丢弃，这个是必须的啊，没有目标输出个什么啊」）。
 * 现网实锤过不丢弃的后果：电脑那根线没插时写回 -ESHUTDOWN，位移照样攒着，
 * 插上电脑的一瞬间在 28 帧里被补投出去（`pending=-273,-1836`，等效约 1800px 瞬移），
 * 而这既不是真人手动能做出的形状，也不是"平滑"。⇒ 判据按错误码分流：
 *   -EAGAIN  = 目标在，只是这一拍没来取 ⇒ **守恒**，原样退回 pending，下一拍接着发；
 *   -ESHUTDOWN / -ENODEV = gadget 没绑定、对面没有主机 ⇒ **整笔丢弃**（含本次与本拍之前的
 *   全部 pending），并计数 `drop`/`drop_units` 留痕。丢掉的必须是看得见的数，
 *   不能静悄悄丢，否则又变成"设备明明在动、页面说从没动过"那一类假死象。
 * 按钮态不在这条里：按下态由 hold_ms 自己到期清零，重连后下一帧按当前真实态重发。
 *
 * ── 不动现役件 ──────────────────────────────────────────────────────
 * 与打过 auth 埋点的 usb_f_hid.ko（naoyun-auth-v3）完全解耦：只当 /dev/hidg1 的普通写者。
 * 默认 enable=0：加载后不注册 input handler、不打开 hidg、不起线程；rmmod 即干净退场。
 *
 * ── 构建口径 ────────────────────────────────────────────────────────
 * 本机内核由 clang 构建（CONFIG_CC_IS_CLANG=y + CONFIG_LTO_CLANG_THIN=y），
 * 顶层 Makefile 会注入 -Qunused-arguments / -mno-global-merge / -fsplit-lto-unit，
 * gcc 不认这些选项。必须 make CC=clang LD=ld.lld LLVM=1，见同目录 Makefile。
 *
 * ── 出帧落地的硬前提：usb_f_hid 必须是 naoyun-auth-v4 及以上 ─────────────
 * 这台盒的内核去掉了 set_fs（实测：内核里没有 get_ds/set_fs，编都编不过），
 * 于是内核态写者拿 /dev/hidg1 的路全被堵：
 *   access_ok(内核指针)=0、直接调 f_hidg_write 传内核指针 = -14(-EFAULT)、
 *   kernel_write() = -22(-EINVAL)（装上 v4、write_iter 已挂上之后**仍** -22，
 *   所以那道门是这台内核 kernel_write 自己的实现问题，与 fops 有没有 write_iter 无关）。
 * 通路 = f_hid 补 .write_iter（=naoyun-auth-v4）+ 本模块直调 write_iter(kvec)：
 *   实测直调回 -108(-ESHUTDOWN)，说明已经进到 __f_hidg_write 的写队列逻辑，
 *   只差 OTG 口没插电脑（hidg->req 为空）。用户态 write() 仍走 .write，一行没动。
 * activate() 先验这个前提：拿不到 .write_iter 就明确报错，绝不连发错帧。
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/fcntl.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/uio.h>		/* kiocb + iov_iter_kvec：直连 f_hid 的 .write_iter 用 */
#include <linux/miscdevice.h>
#include <linux/input.h>
#include <linux/device.h>	/* dev_name()：绑定身份只能从设备名拿 */
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>

#define MODNAME "naoyun_motion"
#define VERSION "naoyun-motion-v5"
#define MAX_LEN 64	/* 一帧最大字节数（configfs report_length 同量级） */
#define BTN_MAX 32
#define LAY_NKEY 11

/* 内核没有 labs()；自己写一个，别指望 stdlib */
static inline long abs_l(long v)
{
	return v < 0 ? -v : v;
}

/*
 * "没有输出目标"的判据：对面根本没主机。
 *   -ESHUTDOWN = gadget 未绑定 UDC（电脑线没插 / 功能已摘）
 *   -ENODEV    = 落点节点已失效（同一类：对面没人收）
 * 与"目标在但这一拍没来取"（-EAGAIN）严格分开——后者必须守恒，前者必须丢，
 * 混在一起就是要么瞬移要么丢真位移。
 */
static inline bool no_target(ssize_t ret)
{
	return ret == -ESHUTDOWN || ret == -ENODEV;
}

/* ── 可调参数（全走 /sys/module/naoyun_motion/parameters/，热调不重编）──── */
static int enable;
module_param(enable, int, 0644);
MODULE_PARM_DESC(enable, "0=挂而不应（默认，加载即零副作用） 1=透传并按节拍出帧");

static char hidg_dev[64] = "/dev/hidg1";
module_param_string(hidg_dev, hidg_dev, sizeof(hidg_dev), 0644);
MODULE_PARM_DESC(hidg_dev, "出帧落点：gadget 鼠标节点，默认 /dev/hidg1");

static int tick_us = 1000;
module_param(tick_us, int, 0644);
MODULE_PARM_DESC(tick_us, "出帧节拍（微秒）：一拍最多一帧。高速 IN 端点 bInterval=4 ⇒ 主机最快每 1ms 取一帧");

/*
 * 节拍夹逼：tick_us 是 0644 能被热调的，不夹一刀会被写成 0 或负数——usleep_range 与
 * msecs_to_jiffies 在那种取值下的语义都不是"节拍"。下限 200µs（比 f_hid 的 1ms 取帧还快
 * 也只是白撞 -EAGAIN），上限 100ms（再慢人手就觉得卡了）。
 */
static int clamp_tick(void)
{
	int t = READ_ONCE(tick_us);

	if (t < 200)
		return 200;
	if (t > 100000)
		return 100000;
	return t;
}

/* 静止等待用 jiffies（向上取整到至少 1 jiffy）；发帧节拍用 usleep_range，见文件头纪律 2 */
static unsigned long tick_jiffies(int us)
{
	return msecs_to_jiffies((us + 999) / 1000);
}

static int alpha = 96;
module_param(alpha, int, 0644);
MODULE_PARM_DESC(alpha, "跟手度 1..255：每拍发出剩余的 alpha/256。小=惯性大 255=原样透传");

static int max_step = 127;
module_param(max_step, int, 0644);
MODULE_PARM_DESC(max_step, "单帧位移上限（像素），超出部分留到下一拍——守恒，不丢");

static int deadzone = 2;
module_param(deadzone, int, 0644);
MODULE_PARM_DESC(deadzone, "剩余位移小于此值就一次发完并停帧，免得亚像素一直抖");

static int hold_ms = 250;
module_param(hold_ms, int, 0644);
MODULE_PARM_DESC(hold_ms, "多久没有新意图就自动松按钮；0=不超时");

static int err_backoff_after = 32;
module_param(err_backoff_after, int, 0644);
MODULE_PARM_DESC(err_backoff_after, "连续写失败多少帧后转入退避（默认 32）；0=不退避");

static int backoff_ms = 200;
module_param(backoff_ms, int, 0644);
MODULE_PARM_DESC(backoff_ms, "退避一睡多久（毫秒）。新意图会立刻 wake 醒它，所以退避不拖后腿");

/*
 * drop_unbound：对面没有主机时（写回 -ESHUTDOWN/-ENODEV）要不要把 pending 直接丢弃。
 * 默认 1 = 丢（用户 2026-10-16 裁定「没有目标输出个什么啊」）；置 0 退回旧的"无脑守恒"，
 * 留着做对照实验用——同一条指令流下看 drop 计数与光标是否瞬移，两种行为必须都能现场切。
 */
static int drop_unbound = 1;
module_param(drop_unbound, int, 0644);
MODULE_PARM_DESC(drop_unbound, "1=无主机时丢弃 pending（默认，防重连瞬移） 0=旧行为：无脑攒着");

static int bind_cpu = 3;
module_param(bind_cpu, int, 0644);
MODULE_PARM_DESC(bind_cpu, "出帧线程绑定的 CPU 核心号：-1=不绑定（由调度器分配），0..N=绑定指定核心（默认 3）");

static int rt_priority = 1;
module_param(rt_priority, int, 0644);
MODULE_PARM_DESC(rt_priority, "是否启用 SCHED_FIFO 实时调度：1=实时优先级（默认），0=普通调度");

/* ── 布局：Go 侧解析报告描述符后下发。内核这层不认 HID 描述符，只认偏移 ── */
struct layout {
	u8 len;		/* 整帧字节数（含 report id 首字节） */
	u8 has_id;
	u8 report_id;
	int btn_bit;
	int btn_count;
	int x_bit;
	int x_size;
	int y_bit;
	int y_size;
	int wheel_bit;
	int wheel_size;
};

static DEFINE_SPINLOCK(st_lock);
static struct layout lay;
static bool layout_ok_;
static long pend_x, pend_y, pend_wheel;
static int btn_mask, btn_sent;
static u64 st_ev_in, st_intent_in, st_frames_ok, st_again, st_shutdown, st_errs,
	   st_snaps, st_layout_sets, st_backoffs;
static u64 st_drop_frames, st_drop_units;	/* 无目标时被丢弃的帧数与位移单位总量 */
static long st_pend_peak;
static int last_err;
static int err_streak;

/* 帧间隔与抖动统计（单位：微秒） */
static u64 last_frame_ns;
static u64 jitter_samples;
static u64 jitter_sum_us;
static u32 jitter_min_us = 0xffffffff;
static u32 jitter_max_us;
static u32 jitter_last_us;
static u64 jitter_spikes; /* 超过 1.5 倍 target 的毛刺数 */

/*
 * 绑定身份用设备名（"input0"/"input1"）记，不记数字：5.15 的 struct input_dev
 * 里没有 number 成员（本机头文件实测：只有 struct input_id id，那是厂商/产品标识，
 * 不是 inputN 的 N）。inputN 这个 N 由 input 核心用 dev_set_name 起，外部模块
 * 唯一稳的拿法就是 dev_name(&dev->dev)。
 */
static char bound_name[32] = "-";

module_param_named(frames_ok, st_frames_ok, ullong, 0444);
module_param_named(frames_again, st_again, ullong, 0444);
module_param_named(frames_shutdown, st_shutdown, ullong, 0444);
module_param_named(frames_err, st_errs, ullong, 0444);
module_param_named(frames_drop, st_drop_frames, ullong, 0444);
module_param_named(drop_units, st_drop_units, ullong, 0444);
module_param_named(events_in, st_ev_in, ullong, 0444);
module_param_named(intent_in, st_intent_in, ullong, 0444);
module_param_named(snap_count, st_snaps, ullong, 0444);
module_param_named(pend_peak, st_pend_peak, long, 0444);
module_param_named(layout_sets, st_layout_sets, ullong, 0444);
module_param_named(backoff_count, st_backoffs, ullong, 0444);
MODULE_PARM_DESC(frames_ok, "成功写出的帧数");
MODULE_PARM_DESC(frames_again, "-EAGAIN 次数：主机没来取（没插电脑/暂停取数），pending 已补回");
MODULE_PARM_DESC(frames_shutdown, "-ESHUTDOWN 次数：gadget 未绑定");
MODULE_PARM_DESC(frames_drop, "因\"没有输出目标\"被丢弃的帧数（-ESHUTDOWN/-ENODEV 且 drop_unbound=1）");
MODULE_PARM_DESC(drop_units, "被丢弃的位移单位总量 |dx|+|dy|+|wheel|（丢了多少，必须看得见）");
MODULE_PARM_DESC(pend_peak, "观测到的最大积压位移（判断节拍是否饱和）");

static DECLARE_WAIT_QUEUE_HEAD(wq);
static struct task_struct *worker;
static struct file *out_filp;
static loff_t out_pos;
static bool active;
static struct input_handler motion_handler;
static struct input_handle *bound_handle;
static u64 last_intent_j;
/*
 * 意图代数：任何一条新意图（位移/滚轮/按钮）都 +1。
 * 退避睡眠拿它当唤醒条件——睡得住（不是一有新数据就条件为真立刻返回），
 * 又能在真鼠标一动就立刻醒，所以退避不给延迟添负担。
 */
static u64 intent_gen;

static int activate(void);
static void deactivate(void);

/* ── 位打包（与 Go 侧 descriptor.go 的 Frame.Set 同一套语义）───────────── */
static void put_bits(u8 *buf, int len, int bit, int size, long v)
{
	int i;

	for (i = 0; i < size; i++) {
		int pos = bit + i;

		if (pos < 0 || pos / 8 >= len)
			return;
		if (v & (1L << i))
			buf[pos / 8] |= (u8)(1 << (pos % 8));
		else
			buf[pos / 8] &= (u8)~(1 << (pos % 8));
	}
}

/* 帧内偏移：位偏移从"去掉 report id 之后"起算，所以有 id 时整体后移一字节 */
static inline int bit_base(void)
{
	return lay.has_id ? 8 : 0;
}

static int build_frame(u8 *out, long dx, long dy, long wheel)
{
	int i;

	if (!layout_ok_ || lay.len > MAX_LEN)
		return 0;
	for (i = 0; i < lay.len; i++)
		out[i] = 0;
	if (lay.has_id)
		out[0] = lay.report_id;
	if (lay.btn_bit >= 0)
		put_bits(out, lay.len, bit_base() + lay.btn_bit,
			 lay.btn_count ? lay.btn_count : 8, btn_mask);
	if (wheel && lay.wheel_bit >= 0 && lay.wheel_size)
		put_bits(out, lay.len, bit_base() + lay.wheel_bit, lay.wheel_size, wheel);
	if (dx && lay.x_bit >= 0 && lay.x_size)
		put_bits(out, lay.len, bit_base() + lay.x_bit, lay.x_size, dx);
	if (dy && lay.y_bit >= 0 && lay.y_size)
		put_bits(out, lay.len, bit_base() + lay.y_bit, lay.y_size, dy);
	return lay.len;
}

/* ── 意图累加（input 事件与指令面共用这一条入口）───────────────────────── */
static void push_intent(long dx, long dy, long wheel, bool from_input)
{
	unsigned long flags;

	spin_lock_irqsave(&st_lock, flags);
	pend_x += dx;
	pend_y += dy;
	pend_wheel += wheel;
	if (abs_l(pend_x) > st_pend_peak)
		st_pend_peak = abs_l(pend_x);
	if (abs_l(pend_y) > st_pend_peak)
		st_pend_peak = abs_l(pend_y);
	if (from_input)
		st_ev_in++;
	else
		st_intent_in++;
	last_intent_j = jiffies;
	intent_gen++;
	spin_unlock_irqrestore(&st_lock, flags);
	wake_up(&wq);	/* 不是 wake_up_interruptible：静止等的是 TASK_UNINTERRUPTIBLE */
}

static void set_button(int idx, int on)
{
	unsigned long flags;

	spin_lock_irqsave(&st_lock, flags);
	if (on)
		btn_mask |= (1 << idx);
	else
		btn_mask &= ~(1 << idx);
	last_intent_j = jiffies;	/* 按下也是一次意图：不然 hold 会把刚按的松开 */
	intent_gen++;
	spin_unlock_irqrestore(&st_lock, flags);
	wake_up(&wq);	/* 不是 wake_up_interruptible：静止等的是 TASK_UNINTERRUPTIBLE */
}

static void clear_all(void)
{
	unsigned long flags;

	spin_lock_irqsave(&st_lock, flags);
	pend_x = pend_y = pend_wheel = 0;
	btn_mask = 0;
	btn_sent = 0;
	intent_gen++;
	spin_unlock_irqrestore(&st_lock, flags);
	wake_up(&wq);	/* 不是 wake_up_interruptible：静止等的是 TASK_UNINTERRUPTIBLE */
}

static bool data_ready(void)
{
	unsigned long flags;
	bool r;

	spin_lock_irqsave(&st_lock, flags);
	r = (pend_x || pend_y || pend_wheel || btn_mask != btn_sent);
	spin_unlock_irqrestore(&st_lock, flags);
	return r;
}

/*
 * 整数指数跟随器：每拍发出剩余的 alpha/256，不足 1 像素时至少挪 1；
 * 剩余 ≤deadzone 一次发完（落点必须精确），超 max_step 的部分留到下一拍（守恒）。
 * 为什么不用计划书里那版二阶临界阻尼：内核没有浮点，定点 ω/ζ 要在 1ms 网格上
 * 反复调比例因子才能不过冲；指数跟随器一个整数 alpha 就同时给了"跟手度"和"惯性"，
 * 且总量守恒天然成立。计划书已按此订正。
 */
static long follow_axis(long *rem)
{
	long r = *rem, a = abs_l(r), step;
	long sgn = (r < 0) ? -1 : 1;

	if (a == 0)
		return 0;
	if (a <= deadzone) {
		step = r;
		*rem = 0;
		st_snaps++;
	} else {
		step = (a * (long)alpha) / 256;
		if (step < 1)
			step = 1;
		if (step > (long)max_step)
			step = max_step;
		if (step > a)
			step = a;
		*rem -= sgn * step;
		step *= sgn;
	}
	return step;
}

/*
 * 出帧落点：直连 f_hid 的 .write_iter，**不用 kernel_write()**。
 * 为什么（`.7` 实测，v4 已装上）：
 *   write_iter=f_hidg_write_iter 挂在 fops 上、kernel_write() 仍回 -22 并打
 *   "kernel write not supported for file /hidg1" ⇒ 这台内核的 kernel_write 那道门
 *   跟 write_iter 存不存在无关，是它自己的实现问题（无 set_fs 的 5.15 移植）。
 *   同一时刻直调 write_iter(kvec) 回 -108(-ESHUTDOWN)——那已经进到 __f_hidg_write 里了，
 *   只是 OTG 口没插电脑（hidg->req 为空）。所以路是通的，被堵的是 VFS 那一层。
 * 代价说清楚：这么走少了 vfs_iter_write 的 rw_verify_area/audit/fsfreeze 记账。
 *   对 hidg 这类字符设备节点这三样本来就不使（无 inode 数据、无 freeze 语义），
 *   且这个 fd 是本模块自己 filp_open 的（O_WRONLY|O_NONBLOCK），不是别人递进来的。
 */
static ssize_t hidg_send(const void *buf, size_t len)
{
	struct iov_iter it;
	struct kiocb kiocb;
	struct kvec kv = { .iov_base = (void *)buf, .iov_len = len };
	ssize_t r;

	if (!out_filp || !out_filp->f_op->write_iter)
		return -EINVAL;	/* f_hid 不是 v4：没有内核态写入口，见 activate() 的告警 */
	init_sync_kiocb(&kiocb, out_filp);
	kiocb.ki_pos = out_pos;
	iov_iter_kvec(&it, WRITE, &kv, 1, len);
	r = out_filp->f_op->write_iter(&kiocb, &it);
	out_pos = kiocb.ki_pos;
	return r;
}

/* ── 节拍线程 ─────────────────────────────────────────────────────── */
static int motion_thread(void *unused)
{
	int last_bound_cpu = -999;
	int last_rt = -999;
	bool unbound_seen = false;	/* 只在节拍线程里读写，不加锁：它自己是唯一读者 */

	while (!kthread_should_stop()) {
		unsigned long flags;
		u8 buf[MAX_LEN];
		long dx = 0, dy = 0, wheel = 0;
		long lost_dx = 0, lost_dy = 0, lost_dw = 0;	/* 本笔丢弃的位移（日志用） */
		int len, prev_sent, tr = 0, streak_was = 0;
		bool first_drop = false;
		int tick = clamp_tick();
		int cur_bind = READ_ONCE(bind_cpu);
		int cur_rt = READ_ONCE(rt_priority);
		ssize_t ret;

		/* 动态同步 CPU 亲和性 */
		if (cur_bind != last_bound_cpu) {
			if (cur_bind >= 0 && cur_bind < nr_cpu_ids && cpu_online(cur_bind)) {
				set_cpus_allowed_ptr(current, cpumask_of(cur_bind));
			} else if (cur_bind < 0) {
				set_cpus_allowed_ptr(current, cpu_online_mask);
			}
			last_bound_cpu = cur_bind;
		}

		/* 动态同步实时调度策略 */
		if (cur_rt != last_rt) {
			if (cur_rt > 0)
				sched_set_fifo(current);
			else
				sched_set_normal(current, 0);
			last_rt = cur_rt;
		}

		if (!READ_ONCE(enable)) {
			if (active)
				deactivate();
			wait_event_timeout(wq,
				READ_ONCE(enable) || kthread_should_stop(),
				msecs_to_jiffies(50));
			continue;
		}
		if (!active) {
			if (activate()) {
				ssleep(1);
				continue;
			}
		}
		if (!layout_ok_) {
			/* 没布局就发帧等于发错帧：等着，不猜一份出来 */
			wait_event_timeout(wq,
				layout_ok_ || kthread_should_stop() ||
				!READ_ONCE(enable), msecs_to_jiffies(200));
			continue;
		}

		/*
		 * 写通道连续失败时（电脑不来取帧 -EAGAIN / gadget 没绑 -ESHUTDOWN /
		 * 内核没有写入口 -EINVAL），1ms 死磕会把 dmesg 刷爆——实测 20 秒 120 万条。
		 * 转退避：睡 backoff_ms，但新意图（intent_gen 变了）立刻把它叫醒，
		 * 所以"少打炮"不等于"变迟钝"。
		 */
		if (err_backoff_after > 0 && err_streak >= err_backoff_after) {
			u64 gen = intent_gen;

			st_backoffs++;
			wait_event_timeout(wq,
				kthread_should_stop() || !READ_ONCE(enable) ||
				intent_gen != gen,
				msecs_to_jiffies(backoff_ms > 0 ? backoff_ms : 200));
			err_streak = 0;
		}

		/*
		 * 静止（无 pending、按钮态也未变）：睡到下一拍，有新意图立刻被 wake_up 叫醒。
		 * 必须用**不可中断**的 wait_event_timeout：interruptible 系列在带挂起信号的
		 * 内核线程里等于不睡（v1 实测 voluntary_ctxt_switches 一秒不增、0.4 核空转，
		 * tick_us 从 1ms 改到 200ms 速率纹丝不动），详见文件头第 2 条纪律。
		 */
		if (!data_ready()) {
			wait_event_timeout(wq,
				data_ready() || kthread_should_stop() || !READ_ONCE(enable),
				tick_jiffies(tick));
			continue;
		}

		spin_lock_irqsave(&st_lock, flags);
		if (hold_ms > 0 && last_intent_j && btn_mask &&
		    time_after(jiffies, (unsigned long)(last_intent_j +
							msecs_to_jiffies(hold_ms))))
			btn_mask = 0;	/* 网络那头断了也别把按钮卡在按下态 */
		prev_sent = btn_sent;
		dx = follow_axis(&pend_x);
		dy = follow_axis(&pend_y);
		wheel = pend_wheel;
		if (wheel) {
			if (lay.wheel_bit < 0 || lay.wheel_size == 0) {
				/* 这只鼠标没有滚轮位：整笔退回，不发错帧也不丢 */
				wheel = 0;
			} else {
				long lim = (1L << (lay.wheel_size - 1)) - 1;
				long w = wheel;

				if (abs_l(w) > lim)
					w = (w < 0) ? -lim : lim;
				pend_wheel -= w;
				wheel = w;	/* 发出去的必须是扣过的那一份 */
			}
		}
		len = (dx || dy || wheel || btn_mask != btn_sent) ?
			build_frame(buf, dx, dy, wheel) : 0;
		if (len)
			btn_sent = btn_mask;
		spin_unlock_irqrestore(&st_lock, flags);

		if (!len)
			continue;

		ret = hidg_send(buf, len);
		spin_lock_irqsave(&st_lock, flags);
		if (ret == (ssize_t)len) {
			u64 now_ns = ktime_get_ns();

			if (last_frame_ns > 0) {
				u64 delta_us = (now_ns - last_frame_ns) / 1000;

				jitter_samples++;
				jitter_sum_us += delta_us;
				jitter_last_us = (u32)delta_us;
				if (delta_us < (u64)jitter_min_us)
					jitter_min_us = (u32)delta_us;
				if (delta_us > (u64)jitter_max_us)
					jitter_max_us = (u32)delta_us;
				if (tick > 0 && delta_us > (u64)(tick + tick / 2))
					jitter_spikes++;
			}
			last_frame_ns = now_ns;

			st_frames_ok++;
			last_err = 0;
			streak_was = err_streak;
			if (err_streak)
				tr = 1;		/* 写通道恢复 */
			err_streak = 0;
			unbound_seen = false;	/* 目标回来了：下次再进"无目标"态要重新留痕 */
		} else {
			/* 没发出去。这里必须按错误码分两条路，绝不无脑退回 pending：
			   -EAGAIN          = 目标在，只是这一拍主机没来取 → 守恒优先，原样退回，下拍再发；
			   -ESHUTDOWN/-ENODEV = 对面根本没有主机（gadget 未绑定 / 落点节点已摘）→
			   连本笔带**全部已积压 pending 一起丢弃**。依据是用户 2026-10-16 裁定：
			   「电脑没连期间不攒 pending 直接丢弃，这个是必须的啊，没有目标输出个什么啊」。
			   不丢的后果现网实锤过：pending=-273,-1836 一直攒着，udc 转 configured 的一瞬
			   在 28 帧内补投出去，等效给电脑来一次约 1800px 的瞬移——那不是人能做出的形状。
			   丢弃量必须看得见：drop/drop_units 计数 + 进入该态的第一笔留一条日志。
			   按钮态仍旧退回"未送"，重连后下一帧按当前真实态重发；按下态另有 hold_ms 到期自清。 */
			btn_sent = prev_sent;
			if (no_target(ret) && READ_ONCE(drop_unbound)) {
				lost_dx = dx + pend_x;
				lost_dy = dy + pend_y;
				lost_dw = wheel + pend_wheel;
				st_drop_units += abs_l(lost_dx) + abs_l(lost_dy) + abs_l(lost_dw);
				st_drop_frames++;
				pend_x = 0;
				pend_y = 0;
				pend_wheel = 0;
				if (!unbound_seen) {
					unbound_seen = true;
					first_drop = true;
				}
				if (ret == -ENODEV)
					st_errs++;
				else
					st_shutdown++;
			} else {
				pend_x += dx;
				pend_y += dy;
				pend_wheel += wheel;
				if (ret == -EAGAIN)
					st_again++;
				else if (ret == -ESHUTDOWN)
					st_shutdown++;
				else
					st_errs++;
			}
			last_err = (int)ret;
			err_streak++;
			if (err_streak == 1)
				tr = 2;
			else if (err_backoff_after > 0 &&
				 err_streak == err_backoff_after)
				tr = 3;
		}
		spin_unlock_irqrestore(&st_lock, flags);

		/* 日志只在状态跳变处打，且在锁外：连错期间一个字都不多打 */
		if (tr == 1)
			pr_info("写通道恢复（此前连错 %d 发）\n", streak_was);
		else if (tr == 2)
			pr_warn("写 %s 失败 ret=%zd（首条留痕，后续连错不再打）\n",
				hidg_dev, ret);
		else if (tr == 3)
			pr_warn("写 %s 连错 %d 发，转退避 %dms（新意图到即醒；ret=%zd）\n",
				hidg_dev, err_backoff_after, backoff_ms, ret);

		/* 进入"无目标丢弃"态单独留痕：它和"第几连错"无关，可能发生在 EAGAIN 之后
		   才转成 ESHUTDOWN 的时刻，挂在 tr 那条链上会被吞掉。*/
		if (first_drop)
			pr_warn("无输出目标 ret=%zd（%s 未绑定或未接主机）：进入丢弃态，"
				"本笔丢 dx=%ld dy=%ld wheel=%ld，累计丢 %llu 帧/%llu 单位；"
				"电脑插回来时不会补投陈旧位移（drop_unbound=0 可切回旧行为对照）\n",
				ret, hidg_dev, lost_dx, lost_dy, lost_dw,
				st_drop_frames, st_drop_units);

		/*
		 * 节拍落地：**一拍最多一帧**。写失败也一样占一拍（那拍的位移已原样退回
		 * pending），所以"守恒"与"节拍"互不妥协。这里用 usleep_range() 而不是
		 * wait_event_*hrtimeout()——后者在内核线程有挂起信号时等于不睡，v1 就是
		 * 这样把 1ms 节拍跑成 0.4 核空转的（实测 voluntary_ctxt_switches 不增、
		 * tick_us 改 200ms 速率不动），见文件头纪律 2。
		 */
		usleep_range(tick, tick + 200);
	}
	return 0;
}

/* ── input handler：真鼠标透传的唯一入口，全程内核 ────────────────────── */
static const struct input_device_id motion_ids[] = {
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT |
			 INPUT_DEVICE_ID_MATCH_KEYBIT |
			 INPUT_DEVICE_ID_MATCH_RELBIT,
		.evbit = { BIT_MASK(EV_KEY) | BIT_MASK(EV_REL) },
		.keybit = { [BIT_WORD(BTN_LEFT)] = BIT_MASK(BTN_LEFT) },
		.relbit = { [BIT_WORD(REL_X)] = BIT_MASK(REL_X) | BIT_MASK(REL_Y) },
	},
	{ }
};

static void motion_event(struct input_handle *handle, unsigned int type,
			 unsigned int code, int value)
{
	if (!READ_ONCE(enable))
		return;
	switch (type) {
	case EV_REL:
		switch (code) {
		case REL_X:
			push_intent(value, 0, 0, true);
			break;
		case REL_Y:
			push_intent(0, value, 0, true);
			break;
		case REL_WHEEL:
			push_intent(0, 0, value, true);
			break;
		case REL_HWHEEL:
			push_intent(0, 0, value, true);
			break;
		}
		return;
	case EV_KEY:
		/*
		 * 只搬 Boot 鼠标认得的三键（BTN_LEFT/RIGHT/MIDDLE）。
		 * 侧键（BTN_SIDE/BTN_EXTRA）要按布局的按钮位图发，那是 4 期把
		 * 这只鼠标的报表整个搬过来之后才成立的事——现在硬发就是错帧。
		 */
		if (code < BTN_LEFT || code > BTN_MIDDLE)
			return;
		set_button(code - BTN_LEFT, value);
		return;
	case EV_SYN:
		return;
	}
}

static int motion_connect(struct input_handler *h, struct input_dev *dev,
			  const struct input_device_id *id)
{
	struct input_handle *handle;
	int err;

	if (bound_handle)
		return -EBUSY;	/* 一次只跟一只鼠标：两只同时动会把落点打糊 */
	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;
	handle->dev = dev;
	handle->handler = h;
	handle->name = h->name;
	err = input_register_handle(handle);
	if (err) {
		kfree(handle);
		return err;
	}
	err = input_open_device(handle);
	if (err) {
		input_unregister_handle(handle);
		kfree(handle);
		return err;
	}
	bound_handle = handle;
	strscpy(bound_name, dev_name(&dev->dev), sizeof(bound_name));
	pr_info("透传已绑定 %s（%s）\n", bound_name, dev->name ? dev->name : "?");
	return 0;
}

static void motion_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	if (handle == bound_handle) {
		bound_handle = NULL;
		strscpy(bound_name, "-", sizeof(bound_name));
	}
	kfree(handle);
	pr_info("透传绑定已释放\n");
}

static void motion_handler_init(void)
{
	memset(&motion_handler, 0, sizeof(motion_handler));
	motion_handler.name = MODNAME;
	motion_handler.event = motion_event;
	motion_handler.connect = motion_connect;
	motion_handler.disconnect = motion_disconnect;
	motion_handler.id_table = motion_ids;
	/*
	 * 故意不设 .match：input_match_device_id() 没导出，外部模块拿不到。
	 * 内核默认 input_match_device_id 走 id_table 比对，效果一致。
	 */
}

/* ── 启停（enable 翻转由节拍线程惰性执行，参数写入不占上下文）───────────── */
static int activate(void)
{
	struct file *f;
	int err;

	/* O_NONBLOCK 是硬要求：主机不取帧时 f_hidg_write 会睡在写队列上 */
	f = filp_open(hidg_dev, O_WRONLY | O_NONBLOCK | O_CLOEXEC, 0);
	if (IS_ERR(f)) {
		err = PTR_ERR(f);
		pr_warn("打开 %s 失败 err=%d：gadget 没建还是线没插？\n", hidg_dev, err);
		last_err = err;
		return err;
	}
	out_filp = f;
	out_pos = 0;
	if (!f->f_op->write_iter) {
		pr_err("%s 没有 .write_iter（f_hid 不是 naoyun-auth-v4）：内核态写入口不存在，"
		       "出帧必然全败。先按 auth 交接文档 §3.2 换 ko\n",
		       hidg_dev);
		last_err = -EINVAL;
		filp_close(out_filp, NULL);
		out_filp = NULL;
		return -EINVAL;
	}
	motion_handler_init();
	err = input_register_handler(&motion_handler);
	if (err) {
		filp_close(out_filp, NULL);
		out_filp = NULL;
		pr_err("input handler 注册失败 err=%d\n", err);
		last_err = err;
		return err;
	}
	active = true;
	clear_all();
	pr_info("已启用：节拍 %dus alpha=%d max_step=%d 落点 %s\n",
		tick_us, alpha, max_step, hidg_dev);
	return 0;
}

static void deactivate(void)
{
	if (!active)
		return;
	input_unregister_handler(&motion_handler);
	active = false;
	if (out_filp) {
		filp_close(out_filp, NULL);
		out_filp = NULL;
	}
	/* input_unregister_handler 已把 handle 走 disconnect 收走，这里只兜底清指针 */
	bound_handle = NULL;
	strscpy(bound_name, "-", sizeof(bound_name));
	pr_info("已停用：线程外的绑定与落点都收干净了\n");
}

/* ── 布局指令：`layout len=5 has_id=0 report_id=0 btn_bit=0 btn_count=5 x_bit=8 ...`
 * 一次收齐 11 项才生效（半套布局比没有布局更危险：它会发得出帧，只是帧是错的）。 */
static const char *const lay_keys[LAY_NKEY] = {
	"len", "has_id", "report_id", "btn_bit", "btn_count",
	"x_bit", "x_size", "y_bit", "y_size", "wheel_bit", "wheel_size"
};

static int apply_layout(char *args)
{
	struct layout nl;
	int got[LAY_NKEY];
	int i;
	char *cur;

	memset(&nl, 0, sizeof(nl));
	memset(got, 0, sizeof(got));
	nl.btn_bit = -1;
	nl.wheel_bit = -1;

	while ((cur = strsep(&args, " \t")) != NULL) {
		char *eq;
		long v;

		if (!*cur)
			continue;
		eq = strchr(cur, '=');
		if (!eq)
			return -EINVAL;
		*eq = '\0';
		if (kstrtol(eq + 1, 10, &v))
			return -EINVAL;
		/* has_id/report_id 缺省为 0 是合法的，但 11 项必须逐项点齐 */
		for (i = 0; i < LAY_NKEY; i++) {
			if (!strcmp(cur, lay_keys[i])) {
				switch (i) {
				case 0: nl.len = (u8)v; break;
				case 1: nl.has_id = (u8)v; break;
				case 2: nl.report_id = (u8)v; break;
				case 3: nl.btn_bit = (int)v; break;
				case 4: nl.btn_count = (u8)v; break;
				case 5: nl.x_bit = (int)v; break;
				case 6: nl.x_size = (u8)v; break;
				case 7: nl.y_bit = (int)v; break;
				case 8: nl.y_size = (u8)v; break;
				case 9: nl.wheel_bit = (int)v; break;
				case 10: nl.wheel_size = (u8)v; break;
				}
				got[i] = 1;
				break;
			}
		}
		if (i == LAY_NKEY)
			return -EINVAL;	/* 认不出的键名：拒收，不静默忽略 */
	}
	for (i = 0; i < LAY_NKEY; i++)
		if (!got[i])
			return -EINVAL;	/* 少一项都不生效 */

	if (nl.len == 0 || nl.len > MAX_LEN || nl.x_size == 0 || nl.y_size == 0)
		return -EINVAL;
	if (nl.has_id && nl.len < 2)
		return -EINVAL;
	if (!nl.has_id && nl.report_id)
		return -EINVAL;
	if (nl.btn_bit < -1 || nl.wheel_bit < -1)
		return -EINVAL;
	if (nl.x_bit + nl.x_size > nl.len * 8 || nl.y_bit + nl.y_size > nl.len * 8)
		return -EINVAL;
	if (nl.btn_bit >= 0 &&
	    nl.btn_bit + max_t(int, (int)nl.btn_count, 1) > nl.len * 8)
		return -EINVAL;
	if (nl.wheel_bit >= 0 && nl.wheel_size &&
	    nl.wheel_bit + nl.wheel_size > nl.len * 8)
		return -EINVAL;

	lay = nl;
	layout_ok_ = true;
	st_layout_sets++;
	pr_info("布局已生效 len=%u id=%u x@%d/%d y@%d/%d btn@%d/%d wheel@%d/%d\n",
		lay.len, lay.report_id, lay.x_bit, lay.x_size, lay.y_bit, lay.y_size,
		lay.btn_bit, lay.btn_count, lay.wheel_bit, lay.wheel_size);
	return 0;
}

/* ── 指令面：/dev/naoyun-motion（一行一条文本，shell 与程序两边都好看好测）──
 * move <dx> <dy> | wheel <notch> | btn <1..32> <0|1> | release | reset |
 * layout k=v ... | zero（计数归零，台架对拍前必做） */
static ssize_t motion_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *offp)
{
	char kbuf[256];
	char *p, *tok, *a1, *a2;
	long v1 = 0, v2 = 0;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	kbuf[count] = '\0';
	p = strim(kbuf);
	tok = strsep(&p, " \t");
	if (!tok || !*tok)
		return -EINVAL;

	if (!strcmp(tok, "layout")) {
		int err = apply_layout(p);

		return err ? err : (ssize_t)count;
	}

	a1 = strsep(&p, " \t");
	a2 = strsep(&p, " \t");
	if (a1 && *a1) {
		if (kstrtol(a1, 10, &v1))
			return -EINVAL;
	}
	if (a2 && *a2) {
		if (kstrtol(a2, 10, &v2))
			return -EINVAL;
	}

	if (!strcmp(tok, "move")) {
		push_intent(v1, v2, 0, false);
	} else if (!strcmp(tok, "wheel")) {
		push_intent(0, 0, v1, false);
	} else if (!strcmp(tok, "btn")) {
		if (v1 < 1 || v1 > BTN_MAX)
			return -EINVAL;
		set_button((int)v1 - 1, v2 != 0);
	} else if (!strcmp(tok, "release")) {
		unsigned long flags;

		spin_lock_irqsave(&st_lock, flags);
		btn_mask = 0;
		last_intent_j = jiffies;
		spin_unlock_irqrestore(&st_lock, flags);
		wake_up(&wq);	/* 不是 wake_up_interruptible：静止等的是 TASK_UNINTERRUPTIBLE */
	} else if (!strcmp(tok, "reset")) {
		clear_all();
	} else if (!strcmp(tok, "zero")) {
		/* 清零计数：台架对拍前必须能把账归零，否则分不清是哪一轮的数 */
		unsigned long flags;

		spin_lock_irqsave(&st_lock, flags);
		st_ev_in = st_intent_in = st_frames_ok = 0;
		st_again = st_shutdown = st_errs = st_snaps = 0;
		st_drop_frames = st_drop_units = 0;
		st_backoffs = 0;
		st_pend_peak = 0;
		err_streak = 0;
		last_err = 0;
		last_frame_ns = 0;
		jitter_samples = 0;
		jitter_sum_us = 0;
		jitter_min_us = 0xffffffff;
		jitter_max_us = 0;
		jitter_last_us = 0;
		jitter_spikes = 0;
		spin_unlock_irqrestore(&st_lock, flags);
	} else {
		return -EINVAL;
	}
	return count;
}

static const struct file_operations motion_fops = {
	.owner = THIS_MODULE,
	.write = motion_write,
	.llseek = no_llseek,
};

static struct miscdevice motion_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "naoyun-motion",
	.fops = &motion_fops,
	.mode = 0600,
};

/* ── 仪表：/sys/kernel/naoyun_motion/stats ───────────────────────────── */
static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	unsigned long flags;
	long px, py, pw;
	int btn, sent;

	spin_lock_irqsave(&st_lock, flags);
	px = pend_x;
	py = pend_y;
	pw = pend_wheel;
	btn = btn_mask;
	sent = btn_sent;
	spin_unlock_irqrestore(&st_lock, flags);
	{
		int cur_cpu = worker ? task_cpu(worker) : -1;
		const char *policy_str = (worker && worker->policy == SCHED_FIFO) ? "FIFO" : "TS";

		return sysfs_emit(buf,
			"enable=%d active=%d bound=%s layout=%d hidg=%s last_err=%d err_streak=%d\n"
			"frames_ok=%llu again=%llu shutdown=%llu err=%llu snaps=%llu backoffs=%llu\n"
			"drop=%llu drop_units=%llu drop_gate=%d\n"
			"events_in=%llu intent_in=%llu layout_sets=%llu\n"
			"pending=%ld,%ld,%ld btn=0x%x sent=0x%x pend_peak=%ld\n"
			"tick_us=%d alpha=%d max_step=%d deadzone=%d hold_ms=%d backoff=%d/%dms\n"
			"sched=%s cpu=%d bind_cpu=%d rt_priority=%d\n"
			"jitter_samples=%llu jitter_last_us=%u jitter_avg_us=%u jitter_min_us=%u jitter_max_us=%u jitter_spikes=%llu\n",
			READ_ONCE(enable), active, bound_name, layout_ok_ ? (int)lay.len : 0,
			hidg_dev, last_err, err_streak,
			st_frames_ok, st_again, st_shutdown, st_errs, st_snaps, st_backoffs,
			st_drop_frames, st_drop_units, READ_ONCE(drop_unbound),
			st_ev_in, st_intent_in, st_layout_sets,
			px, py, pw, btn, sent, st_pend_peak,
			tick_us, alpha, max_step, deadzone, hold_ms,
			err_backoff_after, backoff_ms,
			policy_str, cur_cpu, READ_ONCE(bind_cpu), READ_ONCE(rt_priority),
			jitter_samples, jitter_last_us, jitter_samples ? (u32)(jitter_sum_us / jitter_samples) : 0,
			(jitter_min_us == 0xffffffff) ? 0 : jitter_min_us, jitter_max_us, jitter_spikes);
	}
}
static struct kobj_attribute stats_attr = __ATTR_RO(stats);

static struct attribute *motion_attrs[] = {
	&stats_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(motion);

static struct kobject *motion_kobj;

static int __init motion_init(void)
{
	int err;

	err = misc_register(&motion_misc);
	if (err) {
		pr_err("指令节点 /dev/naoyun-motion 建不起来 err=%d\n", err);
		return err;
	}
	motion_kobj = kobject_create_and_add(MODNAME, kernel_kobj);
	if (!motion_kobj) {
		misc_deregister(&motion_misc);
		return -ENOMEM;
	}
	err = sysfs_create_groups(motion_kobj, motion_groups);
	if (err) {
		kobject_put(motion_kobj);
		motion_kobj = NULL;
		misc_deregister(&motion_misc);
		return err;
	}
	worker = kthread_run(motion_thread, NULL, MODNAME);
	if (IS_ERR(worker)) {
		err = PTR_ERR(worker);
		worker = NULL;
		sysfs_remove_groups(motion_kobj, motion_groups);
		kobject_put(motion_kobj);
		motion_kobj = NULL;
		misc_deregister(&motion_misc);
		return err;
	}
	pr_info("已加载 %s（enable=%d：默认挂而不应——不注册 input handler、不开 %s）\n",
		VERSION, enable, hidg_dev);
	return 0;
}

static void __exit motion_exit(void)
{
	if (worker) {
		kthread_stop(worker);
		worker = NULL;
	}
	deactivate();
	if (motion_kobj) {
		sysfs_remove_groups(motion_kobj, motion_groups);
		kobject_put(motion_kobj);
		motion_kobj = NULL;
	}
	misc_deregister(&motion_misc);
	pr_info("已卸载\n");
}

module_init(motion_init);
module_exit(motion_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NaoYun");
MODULE_VERSION(VERSION);
MODULE_DESCRIPTION("HID 鼠标出帧节拍与真鼠标透传（内核态，不在用户态跑循环）");
