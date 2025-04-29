/** @file bt_drv.h
  *  @brief This header file contains global constant/enum definitions,
  *  global variable declaration.
  *
  *
  * Copyright 2014-2022,2024 NXP
  *
  * This software file (the File) is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the License).  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

#ifndef _BT_DRV_H_
#define _BT_DRV_H_

#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>

#include "hci_wrapper.h"

#ifndef BIT
/** BIT definition */
#define BIT(x) (1UL << (x))
#endif

#ifdef MBT_64BIT
typedef u64 t_ptr;
#else
typedef u32 t_ptr;
#endif

/** max number of adapter supported */
#define MAX_BT_ADAPTER      3
/** Define drv_mode bit */
#define DRV_MODE_BT         BIT(0)

/** Define devFeature bit */
#define DEV_FEATURE_BT     BIT(0)
#define DEV_FEATURE_BTAMP     BIT(1)
#define DEV_FEATURE_BLE     BIT(2)

/** Define maximum number of radio func supported */
#define MAX_RADIO_FUNC     3

/** MAC address print format */
#ifndef MACSTR
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

/** MAC address print arguments */
#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

/** Debug level : Message */
#define	DBG_MSG			BIT(0)
/** Debug level : Fatal */
#define DBG_FATAL		BIT(1)
/** Debug level : Error */
#define DBG_ERROR		BIT(2)
/** Debug level : Data */
#define DBG_DATA		BIT(3)
/** Debug level : Command */
#define DBG_CMD			BIT(4)
/** Debug level : Event */
#define DBG_EVENT		BIT(5)
/** Debug level : Interrupt */
#define DBG_INTR		BIT(6)

/** Debug entry : Data dump */
#define DBG_DAT_D		BIT(16)
/** Debug entry : Data dump */
#define DBG_CMD_D		BIT(17)

/** Debug level : Entry */
#define DBG_ENTRY		BIT(28)
/** Debug level : Warning */
#define DBG_WARN		BIT(29)
/** Debug level : Informative */
#define DBG_INFO		BIT(30)

#ifdef	DEBUG_LEVEL1
extern u32 mbt_drvdbg;

#ifdef	DEBUG_LEVEL2
/** Print informative message */
#define	PRINTM_INFO(msg...)  \
	do {if (mbt_drvdbg & DBG_INFO)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print warning message */
#define	PRINTM_WARN(msg...) \
	do {if (mbt_drvdbg & DBG_WARN)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print entry message */
#define	PRINTM_ENTRY(msg...) \
	do {if (mbt_drvdbg & DBG_ENTRY) \
		printk(KERN_DEBUG msg); } while (0)
#else
/** Print informative message */
#define	PRINTM_INFO(msg...)  do {} while (0)
/** Print warning message */
#define	PRINTM_WARN(msg...)  do {} while (0)
/** Print entry message */
#define	PRINTM_ENTRY(msg...) do {} while (0)
#endif /* DEBUG_LEVEL2 */

/** Print interrupt message */
#define	PRINTM_INTR(msg...)  \
	do {if (mbt_drvdbg & DBG_INTR)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print event message */
#define	PRINTM_EVENT(msg...) \
	do {if (mbt_drvdbg & DBG_EVENT) \
		printk(KERN_DEBUG msg); } while (0)
/** Print command message */
#define	PRINTM_CMD(msg...)   \
	do {if (mbt_drvdbg & DBG_CMD)   \
		printk(KERN_DEBUG msg); } while (0)
/** Print data message */
#define	PRINTM_DATA(msg...)  \
	do {if (mbt_drvdbg & DBG_DATA)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print error message */
#define	PRINTM_ERROR(msg...) \
	do {if (mbt_drvdbg & DBG_ERROR) \
		printk(KERN_ERR msg); } while (0)
/** Print fatal message */
#define	PRINTM_FATAL(msg...) \
	do {if (mbt_drvdbg & DBG_FATAL) \
		printk(KERN_ERR msg); } while (0)
/** Print message */
#define	PRINTM_MSG(msg...)   \
	do {if (mbt_drvdbg & DBG_MSG)   \
		printk(KERN_ALERT msg); } while (0)

/** Print data dump message */
#define	PRINTM_DAT_D(msg...)  \
	do {if (mbt_drvdbg & DBG_DAT_D)  \
		printk(KERN_DEBUG msg); } while (0)
/** Print data dump message */
#define	PRINTM_CMD_D(msg...)  \
	do {if (mbt_drvdbg & DBG_CMD_D)  \
		printk(KERN_DEBUG msg); } while (0)

/** Print message with required level */
#define	PRINTM(level, msg...) PRINTM_##level(msg)

/** Debug dump buffer length */
#define DBG_DUMP_BUF_LEN	64
/** Maximum number of dump per line */
#define MAX_DUMP_PER_LINE	16
/** Maximum data dump length */
#define MAX_DATA_DUMP_LEN	48

static inline void
hexdump(char *prompt, u8 *buf, int len)
{
	int i;
	char dbgdumpbuf[DBG_DUMP_BUF_LEN];
	char *ptr = dbgdumpbuf;

	printk(KERN_DEBUG "%s: len=%d\n", prompt, len);
	for (i = 1; i <= len; i++) {
		ptr += snprintf(ptr, 4, "%02x ", *buf);
		buf++;
		if (i % MAX_DUMP_PER_LINE == 0) {
			*ptr = 0;
			printk(KERN_DEBUG "%s\n", dbgdumpbuf);
			ptr = dbgdumpbuf;
		}
	}
	if (len % MAX_DUMP_PER_LINE) {
		*ptr = 0;
		printk(KERN_DEBUG "%s\n", dbgdumpbuf);
	}
}

/** Debug hexdump of debug data */
#define DBG_HEXDUMP_DAT_D(x, y, z) \
	do {if (mbt_drvdbg & DBG_DAT_D) \
		hexdump(x, y, z); } while (0)
/** Debug hexdump of debug command */
#define DBG_HEXDUMP_CMD_D(x, y, z) \
	do {if (mbt_drvdbg & DBG_CMD_D) \
		hexdump(x, y, z); } while (0)

/** Debug hexdump */
#define	DBG_HEXDUMP(level, x, y, z)    DBG_HEXDUMP_##level(x, y, z)

/** Mark entry point */
#define	ENTER()			PRINTM(ENTRY, "Enter: %s, %s:%i\n", __func__, \
							__FILE__, __LINE__)
/** Mark exit point */
#define	LEAVE()			PRINTM(ENTRY, "Leave: %s, %s:%i\n", __func__, \
							__FILE__, __LINE__)
#else
/** Do nothing */
#define	PRINTM(level, msg...) do {} while (0)
/** Do nothing */
#define DBG_HEXDUMP(level, x, y, z)    do {} while (0)
/** Do nothing */
#define	ENTER()  do {} while (0)
/** Do nothing */
#define	LEAVE()  do {} while (0)
#endif /* DEBUG_LEVEL1 */

/** Bluetooth upload size */
#define	BT_UPLD_SIZE				2312
/** Bluetooth status success */
#define BT_STATUS_SUCCESS			(0)
/** Bluetooth status pending */
#define BT_STATUS_PENDING			(1)
/** Bluetooth status failure */
#define BT_STATUS_FAILURE			(-1)

#ifndef	TRUE
/** True value */
#define TRUE			1
#endif
#ifndef	FALSE
/** False value */
#define	FALSE			0
#endif

/** SD Interface */
#define INTF_SD    BIT(0)
#define IS_SD(ct)   (ct & (INTF_SD << 8))
/** PCIE interface */
#define INTF_PCIE  BIT(1)
#define IS_PCIE(ct)  (ct & (INTF_PCIE << 8))
/** USB Interface */
#define INTF_USB   BIT(2)
#define IS_USB(ct)  (ct & (INTF_USB << 8))

/** 8887 card type */
#define CARD_TYPE_8887   0x01
/** 8897 card type */
#define CARD_TYPE_8897   0x02
/** 8977 card type */
#define CARD_TYPE_8977   0x03
/** 8997 card type */
#define CARD_TYPE_8997   0x04
/** 8987 card type */
#define CARD_TYPE_8987   0x05
/** 9098 card type */
#define CARD_TYPE_9098   0x06
/** 9097 card type */
#define CARD_TYPE_9097   0x07
/** 8978 card type */
#define CARD_TYPE_8978   0x08
/** 9177 card type */
#define CARD_TYPE_9177   0x09
/** IW624 card type */
#define CARD_TYPE_IW624   0x0a
/** IW610 card type */
#define CARD_TYPE_IW610   0x0b

#define INTF_MASK 0xff
#define CARD_TYPE_MASK 0xff

#ifdef USB8897
/** USB8897 card type */
#define CARD_TYPE_USB8897   (CARD_TYPE_8897 | (INTF_USB << 8))
#endif
#ifdef USB8997
/** USB8997 card type */
#define CARD_TYPE_USB8997   (CARD_TYPE_8997 | (INTF_USB << 8))
#endif
#ifdef USB8978
/** USB8978 card type */
#define CARD_TYPE_USB8978   (CARD_TYPE_8978 | (INTF_USB << 8))
#endif

/** USBUSB9097 card type */
#define CARD_TYPE_USB9097       (CARD_TYPE_9097 | (INTF_USB << 8))
/** PCIEUSB9097 card type */
#define CARD_TYPE_PCIEUSB9097   (CARD_TYPE_9097 | ((INTF_USB|INTF_PCIE) << 8))

#ifdef USBIW624
/** USBUSBIW624 card type */
#define CARD_TYPE_USBIW624       (CARD_TYPE_IW624 | (INTF_USB << 8))
#endif

#ifdef USBIW610
/** USBIW610 card type */
#define CARD_TYPE_USBIW610       (CARD_TYPE_IW610 | (INTF_USB << 8))
#endif

#ifdef USB9098
/** USBUSB9098 card type */
#define CARD_TYPE_USB9098       (CARD_TYPE_9098 | (INTF_USB << 8))
/** PCIEUSB9098 card type */
#define CARD_TYPE_PCIEUSB9098   (CARD_TYPE_9098 | ((INTF_USB|INTF_PCIE) << 8))
#endif

#ifdef USB8897
#define IS_USB8897(ct) (CARD_TYPE_USB8897 == (ct))
#endif

#ifdef USB8997
#define IS_USB8997(ct) (CARD_TYPE_USB8997 == (ct))
#endif

#ifdef USB8978
#define IS_USB8978(ct) (CARD_TYPE_USB8978 == (ct))
#endif

#define IS_USB9097(ct) (CARD_TYPE_USB9097 == (ct) || CARD_TYPE_PCIEUSB9097 == (ct))

#ifdef USBIW624
#define IS_USBIW624(ct) (CARD_TYPE_USBIW624 == (ct))
#endif

#ifdef USBIW610
#define IS_USBIW610(ct) (CARD_TYPE_USBIW610 == (ct))
#endif

#ifdef USB9098
#define IS_USB9098(ct) (CARD_TYPE_USB9098 == (ct))
#endif

#ifdef USB8897
/** USB8897 Card */
#define CARD_USB8897     "USB8897"
#endif

#ifdef USB8997
/** USB8997 Card */
#define CARD_USB8997     "USB8997"
#endif

#ifdef USB8978
/** USB8978 Card */
#define CARD_USB8978     "USBIW416"
#endif

/** USB9097 Card */
#define CARD_USB9097     "USBIW620"

#ifdef USBIW624
/** USBIW624 Card */
#define CARD_USBIW624     "USBIW624"
#endif

#ifdef USBIW610
/** USBIW610 Card */
#define CARD_USBIW610     "USBIW610"
#endif

#ifdef USB9098
/** USB9098 Card */
#define CARD_USB9098     "USB9098"
#endif

/** 9098 A0 revision num */
#define CHIP_9098_REV_A0    1

/** 9098 A1 revision num */
#define CHIP_9098_REV_A1    2

/** 9098 A0 revision num */
#define CHIP_9097_REV_B0    1

/** card type entry */
typedef struct _card_type_entry {
	u16 card_type;
	u16 func_id;
	char *name;
} card_type_entry;

/** Set thread state */
#define OS_SET_THREAD_STATE(x)		set_current_state(x)
/** Time to wait until Host Sleep state change in millisecond */
#define WAIT_UNTIL_HS_STATE_CHANGED 2000
/** Time to wait cmd resp in millisecond */
#define WAIT_UNTIL_CMD_RESP	    5000

/** Sleep until a condition gets true or a timeout elapses */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
#define os_wait_interruptible_timeout(waitq, cond, timeout) \
	interruptible_sleep_on_timeout(&waitq, ((timeout) * HZ / 1000))
#else
#define os_wait_interruptible_timeout(waitq, cond, timeout) \
	wait_event_interruptible_timeout(waitq, cond, ((timeout) * HZ / 1000))
#endif

#define os_wait_timeout(waitq, cond, timeout) \
         wait_event_timeout(waitq, cond, ((timeout) * HZ / 1000))

typedef struct {
	/** Task */
	struct task_struct *task;
	/** Queue */
	wait_queue_head_t waitQ;
	/** PID */
	pid_t pid;
	/** Private structure */
	void *priv;
} bt_thread;

static inline void
bt_activate_thread(bt_thread *thr)
{
	/** Initialize the wait queue */
	init_waitqueue_head(&thr->waitQ);

	/** Record the thread pid */
	thr->pid = current->pid;
}

static inline void
bt_deactivate_thread(bt_thread *thr)
{
	thr->pid = 0;
	return;
}

static inline void
bt_create_thread(int (*btfunc)(void *), bt_thread *thr, char *name)
{
	thr->task = kthread_run(btfunc, thr, "%s", name);
}

static inline int
bt_terminate_thread(bt_thread *thr)
{
	/* Check if the thread is active or not */
	if (!thr->pid)
		return -1;

	kthread_stop(thr->task);
	return 0;
}

static inline void
os_sched_timeout(u32 millisec)
{
	set_current_state(TASK_INTERRUPTIBLE);

	schedule_timeout((millisec * HZ) / 1000);
}

#ifndef __ATTRIB_ALIGN__
#define __ATTRIB_ALIGN__ __attribute__((aligned(4)))
#endif

#ifndef __ATTRIB_PACK__
#define __ATTRIB_PACK__ __attribute__((packed))
#endif

/** Data structure for the NXP Bluetooth device */
typedef struct _bt_dev {
	/** device name */
	char name[DEV_NAME_LEN];
	/** card pointer */
	void *card;
	/** IO port */
	u32 ioport;

	struct m_dev m_dev[MAX_RADIO_FUNC];

	/** Tx download ready flag */
	u8 tx_dnld_rdy;
	/** Function */
	u8 fn;
	/** Rx unit */
	u8 rx_unit;
	/** Power Save mode : Timeout configuration */
	u16 idle_timeout;
	/** Power Save mode */
	u8 psmode;
	/** Power Save command */
	u8 pscmd;
	/** Host Sleep mode */
	u8 hsmode;
	/** Host Sleep command */
	u8 hscmd;
	/** Low byte is gap, high byte is GPIO */
	u16 gpio_gap;
	/** Host Sleep configuration command */
	u8 hscfgcmd;
	/** Host Send Cmd Flag		 */
	u8 sendcmdflag;
	/** opcode for Send Cmd */
	u16 send_cmd_opcode;
	/** Device Type			*/
	u8 devType;
	/** Device Features    */
	u8 devFeature;
	/** Test mode command */
	u8 test_mode;
} bt_dev_t, *pbt_dev_t;

#define FW_NAMW_MAX_LEN    64

/** card info */
typedef struct _card_info {
	/* FW Name */
	char fw_name[FW_NAMW_MAX_LEN];	// DEFAULT_FW_NAME
	char fw_name_bt[FW_NAMW_MAX_LEN];	// DEFAULT_BT_FW_NAME
} card_info;

typedef struct _bt_private bt_private;
/** Operation data structure for BT bus interfaces */
typedef struct _bt_if_ops {
	/** bt driver calls this function to register the device  */
	int (*register_dev)(bt_private *priv);
	/** bt driver calls this function to unregister the device */
	int (*unregister_dev)(bt_private *priv);
	/** This function initializes firmware */
	int (*download_fw)(bt_private *priv);
	/** Configures hardware to quit deep sleep state */
	int (*wakeup_firmware)(bt_private *priv);
	/** This function is used to send the data/cmd to hardware */
	int (*host_to_card)(bt_private *priv, struct sk_buff * skb);
	/** This function reads the current interrupt status register */
	int (*get_int_status)(bt_private *priv);
	/** check interupt status */
	int (*check_int_status)(bt_private *priv);
	/** get device info */
	int (*get_device)(bt_private *priv);
	/** This function disables the host interrupts */
	int (*disable_host_int)(bt_private *priv);
	/** This function enables the host interrupts */
	int (*enable_host_int)(bt_private *priv);
} bt_if_ops;

/**  Extended flags */
enum ext_mod_params {
	EXT_FW,
	EXT_PSMODE,
	EXT_DEEP_SLEEP,
	EXT_BTPMIC,
	EXT_BT_FW_SERIAL,
	EXT_BT_REQ_FW_NOWAIT,
	EXT_BT_BLOCK_CMD,
	EXT_MAX_PARAM
};

typedef struct _bt_module_param {
	u8 ext_flgs[DIV_ROUND_UP(EXT_MAX_PARAM, 8)];
	char *init_cmds;
	char *init_cfg;
	char *cal_cfg;
	char *cal_cfg_ext;
	char *cal_cfg_ext2;
	char *bt_mac;
	int drv_mode;
	int bt_fw_reload;
	int mbt_gpio_pin;
	int btindrst;
	char *fw_name;
} bt_module_param;

typedef struct _bt_adapter {
	/** Card type */
	u16 card_type;
	/** Card info */
	card_info *card_info;
#ifdef USB
	/** usb device */
	const struct usb_card *pcard_usb;
#endif
	/** Chip revision ID */
	u8 chip_rev;
	/** IRQ number */
	int irq;
	/** Interrupt counter */
	u32 IntCounter;
	/** Tx packet queue */
	struct sk_buff_head tx_queue;

	/** Pointer of fw dump file name */
	char *fwdump_fname;
	/** Pending Tx packet queue */
	struct sk_buff_head pending_queue;
	/** tx lock flag */
	u8 tx_lock;
	/** Power Save mode */
	u8 psmode;
	/** Power Save state */
	u8 ps_state;
	/** Host Sleep state */
	u8 hs_state;
	/** hs skip count */
	u32 hs_skip;
	/** suspend_fail flag */
	u8 suspend_fail;
	/** suspended flag */
	u8 is_suspended;
	/** Number of wakeup tries */
	u8 WakeupTries;
	/** Host Sleep wait queue */
	wait_queue_head_t cmd_wait_q __ATTRIB_ALIGN__;
	/** Host Cmd complet state */
	u8 cmd_complete;
	/** indicate using wait event timeout */
	u8 wait_event_timeout;
	/** int status */
	u32 ireg;
	/** tx pending */
	u32 skb_pending;
/** Version string buffer length */
#define MAX_VER_STR_LEN         128
	/** Driver version */
	u8 drv_ver[MAX_VER_STR_LEN];
	/** Number of command timeout */
	u32 num_cmd_timeout;
	/* module parameter data */
	const struct firmware *param_data;
	/* bus interface operations */
	bt_if_ops ops;
	/* wrapped module parameters */
	bt_module_param params;
	/* block id in module param config file */
	int blk_id;
} bt_adapter, *pbt_adapter;

/** Length of prov name */
#define PROC_NAME_LEN				32

struct item_data {
	/** Name */
	char name[PROC_NAME_LEN];
	/** Size */
	u32 size;
	/** Address */
	t_ptr addr;
	/** Offset */
	u32 offset;
	/** Flag */
	u32 flag;
};

struct proc_private_data {
	/** Name */
	char name[PROC_NAME_LEN];
	/** File flag */
	u32 fileflag;
	/** Buffer size */
	u32 bufsize;
	/** Number of items */
	u32 num_items;
	/** Item data */
	struct item_data *pdata;
	/** Private structure */
	struct _bt_private *pbt;
	/** File operations */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	const struct proc_ops *fops;
#else
	const struct file_operations *fops;
#endif
};

struct device_proc {
	/** Proc directory entry */
	struct proc_dir_entry *proc_entry;
	/** num of proc files */
	u8 num_proc_files;
	/** pointer to proc_private_data */
	struct proc_private_data *pfiles;
};

/** timeval */
typedef struct {
	/** Time (seconds) */
	u32 time_sec;
	/** Time (micro seconds) */
	u32 time_usec;
} bt_timeval;

/** Private structure for the MV device */
typedef struct _bt_private {
	/** Bluetooth device */
	bt_dev_t bt_dev;
	/** Adapter */
	bt_adapter *adapter;
    /** Surprise removed flag */
	u8 SurpriseRemoved;
	/** Firmware helper */
	const struct firmware *fw_helper;
	/** Firmware */
	const struct firmware *firmware;
	/** Init user configure file */
	const struct firmware *init_user_cfg;
	/** Init user configure wait queue token */
	u16 init_user_conf_wait_flag;
	/** Init user configure file wait queue */
	wait_queue_head_t init_user_conf_wait_q __ATTRIB_ALIGN__;
	/** Firmware request start time */
	bt_timeval req_fw_time;
	/** Hotplug device */
	struct device *hotplug_device;
	/** thread to service interrupts */
	bt_thread MainThread;
	 /** proc data */
	struct device_proc dev_proc[MAX_RADIO_FUNC];
	/** Driver lock */
	spinlock_t driver_lock;
	/** Driver lock flags */
	ulong driver_flags;
	/** Driver reference flags */
	struct kobject kobj;
	u8 fw_reload;
    /** fw dump state */
	u8 fw_dump;
} bt_private, *pbt_private;

/** Disable interrupt */
#define OS_INT_DISABLE	spin_lock_irqsave(&priv->driver_lock, \
						priv->driver_flags)
/** Enable interrupt */
#define	OS_INT_RESTORE	spin_unlock_irqrestore(&priv->driver_lock, \
						priv->driver_flags)

#ifndef HCI_BT_AMP
/** BT_AMP flag for device type */
#define  HCI_BT_AMP		0x80
#endif

/** Device type of BT */
#define DEV_TYPE_BT		0x00
/** Device type of AMP */
#define DEV_TYPE_AMP		0x01

/** NXP vendor packet */
#define MRVL_VENDOR_PKT			0xFE

/** Bluetooth command : Get FW Version */
#define BT_CMD_GET_FW_VERSION       0x0F
/** Bluetooth command : Sleep mode */
#define BT_CMD_AUTO_SLEEP_MODE		0x23
/** Bluetooth command : Host Sleep configuration */
#define BT_CMD_HOST_SLEEP_CONFIG	0x59
/** Bluetooth command : Host Sleep enable */
#define BT_CMD_HOST_SLEEP_ENABLE	0x5A
/** Bluetooth command : Module Configuration request */
#define BT_CMD_MODULE_CFG_REQ		0x5B

/** Bluetooth command : PMIC Configure */
#define BT_CMD_PMIC_CONFIGURE           0x7D

/** Bluetooth command : Set Evt Filter Command */
#define BT_CMD_SET_EVT_FILTER		0x05
/** Bluetooth command : Enable Write Scan Command */
#define BT_CMD_ENABLE_WRITE_SCAN	0x1A
/** Bluetooth command : Enable Device under test mode */
#define BT_CMD_ENABLE_DEVICE_TESTMODE	0x03
/** Sub Command: Module Bring Up Request */
#define MODULE_BRINGUP_REQ		0xF1
/** Sub Command: Module Shut Down Request */
#define MODULE_SHUTDOWN_REQ		0xF2
/** Module already up */
#define MODULE_CFG_RESP_ALREADY_UP      0x0c
/** Sub Command: Host Interface Control Request */
#define MODULE_INTERFACE_CTRL_REQ	0xF5

/** Bluetooth event : Power State */
#define BT_EVENT_POWER_STATE		0x20

/** Bluetooth Power State : Enable */
#define BT_PS_ENABLE			0x02
/** Bluetooth Power State : Disable */
#define BT_PS_DISABLE			0x03
/** Bluetooth Power State : Sleep */
#define BT_PS_SLEEP			0x01
/** Bluetooth Power State : Awake */
#define BT_PS_AWAKE			0x02

/** Vendor OGF */
#define VENDOR_OGF				0x3F
/** OGF for reset */
#define RESET_OGF		0x03
/** Bluetooth command : Reset */
#define BT_CMD_RESET	0x03

/** Host Sleep activated */
#define HS_ACTIVATED			0x01
/** Host Sleep deactivated */
#define HS_DEACTIVATED			0x00

/** Power Save sleep */
#define PS_SLEEP			0x01
/** Power Save awake */
#define PS_AWAKE			0x00

/** bt header length */
#define BT_HEADER_LEN			4

#ifndef MAX
/** Return maximum of two */
#define MAX(a, b)		((a) > (b) ? (a) : (b))
#endif

/** This is for firmware specific length */
#define EXTRA_LEN	36

/** Command buffer size for NXP driver */
#define MRVDRV_SIZE_OF_CMD_BUFFER       (2 * 1024)

/** Bluetooth Rx packet buffer size for NXP driver */
#define MRVDRV_BT_RX_PACKET_BUFFER_SIZE \
	(HCI_MAX_FRAME_SIZE + EXTRA_LEN)

/** Request FW timeout in second */
#define REQUEST_FW_TIMEOUT		30

/** The number of times to try when polling for status bits */
#define MAX_POLL_TRIES			100

/** The number of times to try when waiting for downloaded firmware to
    become active when multiple interface is present */
#define MAX_MULTI_INTERFACE_POLL_TRIES  150

/** The number of times to try when waiting for downloaded firmware to
     become active. (polling the scratch register). */
#define MAX_FIRMWARE_POLL_TRIES		100

/** default idle time */
#define DEFAULT_IDLE_TIME           1000

#define BT_CMD_HEADER_SIZE    3

#define BT_CMD_DATA_LEN    128
#define BT_EVT_DATA_LEN    8

/** BT command structure */
typedef struct _BT_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** Data */
	u8 data[BT_CMD_DATA_LEN];
} __ATTRIB_PACK__ BT_CMD;

/** BT event structure */
typedef struct _BT_EVENT {
	/** Event Counter */
	u8 EC;
	/** Length */
	u8 length;
	/** Data */
	u8 data[BT_EVT_DATA_LEN];
} BT_EVENT;

#define DEF_GPIO_GAP        0x0d64

/**
 *  @brief set extended flag in bitmap
 *
 *  @param dev      A pointer to bt_private structure
 *  @param idx      extended flags id
 *  @return	    N/A
 */
static inline void
bt_extflg_set(bt_private *priv, enum ext_mod_params idx)
{
	u8 *ext_fbyte;
	bt_adapter *adapter = priv->adapter;
	ext_fbyte = &adapter->params.ext_flgs[idx / 8];
	*ext_fbyte |= BIT(idx % 8);
}

/**
 *  @brief clear extended flag in bitmap
 *
 *  @param dev		A pointer to bt_private structure
 *  @param idx      	extended flags id
 *  @return		N/A
 */
static inline void
bt_extflg_clear(bt_private *priv, enum ext_mod_params idx)
{
	u8 *ext_fbyte;
	bt_adapter *adapter = priv->adapter;
	ext_fbyte = &adapter->params.ext_flgs[idx / 8];
	*ext_fbyte &= ~BIT(idx % 8);
}

/**
 *  @brief check value of extended flag in bitmap
 *
 *  @param dev		A pointer to bt_private structure
 *  @param idx      	extended flags id
 *  @return		value of extended flag
 */
static inline u8
bt_extflg_isset(bt_private *priv, enum ext_mod_params idx)
{
	u8 ext_fbyte;
	bt_adapter *adapter = priv->adapter;
	ext_fbyte = adapter->params.ext_flgs[idx / 8];
	return (ext_fbyte & BIT(idx % 8)) != 0;
}

void sbi_dup_string(char **dst, char *src);

/** This function verify the received event pkt */
int check_evtpkt(bt_private *priv, struct sk_buff *skb);

/* Prototype of global function */
/** This function gets the priv reference */
struct kobject *bt_priv_get(bt_private *priv);
/** This function release the priv reference */
void bt_priv_put(bt_private *priv);
/** This function adds the card */
bt_private *bt_add_card(void *card, struct device *dev, bt_if_ops * ops,
			u16 card_type);
/** This function removes the card */
int bt_remove_card(void *card);
/** This function handles the interrupt */
void bt_interrupt(struct m_dev *m_dev);

/** This function creates proc interface directory structure */
int bt_root_proc_init(void);
/** This function removes proc interface directory structure */
int bt_root_proc_remove(void);
/** This function initializes proc entry */
int bt_proc_init(bt_private *priv, struct m_dev *m_dev, int seq);
/** This function removes proc interface */
void bt_proc_remove(bt_private *priv);

/** This function process the received event */
int bt_process_event(bt_private *priv, struct sk_buff *skb);
/** This function enables host sleep */
int bt_enable_hs(bt_private *priv, bool is_shutdown);
/** This function used to send command to firmware */
int bt_prepare_command(bt_private *priv);
/** This function frees the structure of adapter */
void bt_free_adapter(bt_private *priv);
/** This function handle the receive packet */
void bt_recv_frame(bt_private *priv, struct sk_buff *skb);
/** This function init module parameters */
int bt_init_module_param(struct device *dev, bt_private *priv);
/** This function free module parameters memory*/
void bt_free_module_param(bt_private *priv);
/** This function read the initial parameter from device tress */
void bt_init_from_dev_tree(void);
void bt_store_firmware_dump(bt_private *priv, u8 *buf, u32 len);

/** clean up m_devs */
void clean_up_m_devs(bt_private *priv);
#ifdef USB
/** bt driver call this function to register to bus driver */
int *sbi_usb_register(void);
/** bt driver call this function to unregister to bus driver */
void sbi_usb_unregister(void);
#endif
/** Module configuration and register device */
int sbi_register_conf_dpc(bt_private *priv);

/** out band reset with interface re-emulation */
#define FW_RELOAD_WITH_EMULATION 3
/** This function reload firmware */
void bt_request_fw_reload(bt_private *priv, int mode);

#ifdef USB
/** This function flushes anchored Tx URBs */
int usb_flush(bt_private *priv);
void usb_free_frags(bt_private *priv);
#ifdef USB_SCO_SUPPORT
void usb_notify(bt_private *priv, unsigned int evt);
void usb_char_notify(bt_private *priv, unsigned int arg);
#endif /* USB_SCO_SUPPORT */

#endif /* USB */

/** Max line length allowed in init config file */
#define MAX_LINE_LEN        256
/** Max MAC address string length allowed */
#define MAX_MAC_ADDR_LEN    18
/** Max register type/offset/value etc. parameter length allowed */
#define MAX_PARAM_LEN       12

/** Bluetooth command : Mac address configuration */
#define BT_CMD_CONFIG_MAC_ADDR		0x22
/** Bluetooth command : Write CSU register */
#define BT_CMD_CSU_WRITE_REG		0x66
/** Bluetooth command : Load calibrate data */
#define BT_CMD_LOAD_CONFIG_DATA     0x61
/** Bluetooth command : Load calibrate ext data */
#define BT_CMD_LOAD_CONFIG_DATA_EXT     0x60
#define HCI_CMD_MARVELL_STORE_CAL_DATA_ANNEX_100     0xFF

/** Bluetooth command : BLE deepsleep */
#define BT_CMD_BLE_DEEP_SLEEP       0x8b

typedef struct _BT_BLE_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** deepsleep flag */
	u8 deepsleep;
} __ATTRIB_PACK__ BT_BLE_CMD;

typedef struct _BT_CSU_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** reg type */
	u8 type;
	/** address */
	u8 offset[4];
	/** Data */
	u8 value[2];
} __ATTRIB_PACK__ BT_CSU_CMD;

/** This function sets mac address */
int bt_set_mac_address(bt_private *priv, u8 *mac);
/** This function writes value to CSU registers */
int bt_write_reg(bt_private *priv, u8 type, u32 offset, u16 value);
/** BT set user defined init data and param */
int bt_init_config(bt_private *priv, char *cfg_file);
/** BT set uer defined init commands */
int bt_init_cmds(bt_private *priv, char *init_cmds_file);
/** BT process command */
int bt_process_commands(bt_private *priv, u8 *cmd_data, u32 cmd_len);
/** BT PMIC Configure command */
int bt_pmic_configure(bt_private *priv);
/** This function load the calibrate data */
int bt_load_cal_data(bt_private *priv, u8 *config_data, u8 *mac);
/** This function load the calibrate ext data */
int bt_load_cal_data_ext(bt_private *priv, u8 *config_data, u32 cfg_data_len,
			 int cfg_ext2);
/** BT set user defined calibration data */
int bt_cal_config(bt_private *priv, char *cfg_file, char *mac);
/** BT set user defined calibration ext data */
int bt_cal_config_ext(bt_private *priv, char *cfg_file, int cfg_ext2);
int bt_init_mac_address(bt_private *priv, char *mac);
int bt_set_gpio_pin(bt_private *priv);
/** Bluetooth command : Set gpio pin */
#define BT_CMD_SET_GPIO_PIN     0xEC
/** Interrupt Raising Edge**/
#define INT_RASING_EDGE  0
/** Interrupt Falling Edge**/
#define INT_FALLING_EDGE 1
#define DELAY_50_US      50

int bt_set_independent_reset(bt_private *priv);
/** Bluetooth command : Independent reset */
#define BT_CMD_INDEPENDENT_RESET     0x0D

typedef struct _BT_HCI_CMD {
	/** OCF OGF */
	u16 ocf_ogf;
	/** Length */
	u8 length;
	/** cmd type */
	u8 cmd_type;
	/** cmd len */
	u8 cmd_len;
	/** Data */
	u8 data[6];
} __ATTRIB_PACK__ BT_HCI_CMD;

static inline void
get_monotonic_time(bt_timeval * tv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	struct timespec64 ts;
#else
	struct timespec ts;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
	ktime_get_raw_ts64(&ts);
#else
	getrawmonotonic(&ts);
#endif
	if (tv) {
		tv->time_sec = (u32)ts.tv_sec;
		tv->time_usec = (u32)ts.tv_nsec / 1000;
	}
}

/* Function declarations added to avoid the build failure against recent keernel 6.9.10 */
int bt_save_dump_info_to_file(char *dir_name, char *file_name, u8 *buf,
			      u32 buf_len);
int bt_send_reset_command(bt_private *priv);
int bt_send_module_cfg_cmd(bt_private *priv, int subcmd);
int bt_enable_ps(bt_private *priv);
int bt_send_hscfg_cmd(bt_private *priv);
int bt_set_evt_filter(bt_private *priv);
int bt_enable_write_scan(bt_private *priv);
int bt_enable_device_under_testmode(bt_private *priv);
int bt_enable_test_mode(bt_private *priv);
int bt_set_ble_deepsleep(bt_private *priv, int mode);
int bt_get_fw_version(bt_private *priv);
void bt_restore_tx_queue(bt_private *priv);
void mdev_query(struct m_dev *m_dev, void *arg);
void init_m_dev(bt_private *priv, struct m_dev *m_dev);
int bt_init_cmd(bt_private *priv);
void bt_send_hw_remove_event(bt_private *priv);
int string_to_number(char *s);
int parse_cfg_get_line(u8 *data, u32 size, u8 *line_pos);
int bt_process_cal_cfg(bt_private *priv, u8 *data, u32 size, char *mac);
int bt_process_init_cfg(bt_private *priv, u8 *data, u32 size);
int bt_process_cal_cfg_ext(bt_private *priv, u8 *data, u32 size, int cfg_ext2);
int bt_validate_cfg_id(bt_private *priv);
int bt_cfg_fallback_process(bt_private *priv);
int parse_skip_cfg_block(u8 *data, u32 size);

#endif /* _BT_DRV_H_ */
