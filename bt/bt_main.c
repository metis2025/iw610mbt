/** @file bt_main.c
  *
  * @brief This file contains the major functions in BlueTooth
  * driver. It includes init, exit, open, close and main
  * thread etc..
  *
  *
  * Copyright 2014-2024 NXP
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
/**
  * @mainpage M-BT Linux Driver
  *
  * @section overview_sec Overview
  *
  * The M-BT is a Linux reference driver for NXP Bluetooth chipset.
  *
  * @section copyright_sec Copyright
  *
  * Copyright 2014-2024 NXP
  *
  */

#include <linux/module.h>

#include "bt_drv.h"
#include "mbt_char.h"

#ifdef USB
#include "bt_usb.h"
#endif

/** Version */
#define VERSION "MX007"

/** global param: fw reload flag */
extern int bt_fw_reload;

/** Driver version */
char mbt_driver_version[] = "---------%s-" VERSION "-(" "FP" FPNUM ")"
#ifdef DEBUG_LEVEL2
	"-dbg"
#endif
	" ";

/** Declare and initialize fw_version */
static char fw_version[32] = "0.0.0.p0";

#define AID_SYSTEM        1000	/* system server */

#define AID_BLUETOOTH     1002	/* bluetooth subsystem */

#define AID_NET_BT_STACK  3008	/* bluetooth stack */

/** Define module name */

#define MODULE_NAME  "bt_fm_nfc"

/** Declaration of chardev class */
static struct class *chardev_class;

/** Interface specific variables */

/**
 * The global variable of a pointer to bt_private
 * structure variable
 **/
bt_private *m_priv[MAX_BT_ADAPTER];

/** Offset of sequence number in event */
#define OFFSET_SEQNUM 4

/**
 *  @brief handle received packet
 *  @param priv    A pointer to bt_private structure
 *  @param skb     A pointer to rx skb
 *
 *  @return        N/A
 */
void
bt_recv_frame(bt_private *priv, struct sk_buff *skb)
{
	struct hci_dev *hdev = NULL;
	if (priv->bt_dev.m_dev[BT_SEQ].spec_type == BLUEZ_SPEC)
		hdev = (struct hci_dev *)priv->bt_dev.m_dev[BT_SEQ].dev_pointer;
	if (hdev) {
		skb->dev = (void *)hdev;
		hdev->stat.byte_rx += skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
		hci_recv_frame(skb);
#else
		hci_recv_frame(hdev, skb);
#endif
	}
	return;
}

/**
 *  @brief Alloc bt device
 *
 *  @return    pointer to structure mbt_dev or NULL
 */
struct mbt_dev *
alloc_mbt_dev(void)
{
	struct mbt_dev *mbt_dev;
	ENTER();

	mbt_dev = kzalloc(sizeof(struct mbt_dev), GFP_KERNEL);
	if (!mbt_dev) {
		LEAVE();
		return NULL;
	}

	LEAVE();
	return mbt_dev;
}

/**
 *  @brief Frees m_dev
 *
 *  @return    N/A
 */
void
free_m_dev(struct m_dev *m_dev)
{
	ENTER();
	kfree(m_dev->dev_pointer);
	m_dev->dev_pointer = NULL;
	LEAVE();
}

/**
 *  @brief clean up m_devs
 *
 *  @return    N/A
 */
void
clean_up_m_devs(bt_private *priv)
{
	struct m_dev *m_dev = NULL;
	struct hci_dev *hdev = NULL;

	ENTER();
	if (priv->bt_dev.m_dev[BT_SEQ].dev_pointer) {
		m_dev = &(priv->bt_dev.m_dev[BT_SEQ]);
		PRINTM(MSG, "BT: Delete %s\n", m_dev->name);
		if (m_dev->spec_type == BLUEZ_SPEC) {
			hdev = (struct hci_dev *)m_dev->dev_pointer;
			/** check if dev->name has been assigned */
			if (strstr(hdev->name, "hci"))
				hci_unregister_dev(hdev);
			hci_free_dev(hdev);
		}
		priv->bt_dev.m_dev[BT_SEQ].dev_pointer = NULL;
	}
	LEAVE();
	return;
}

/**
 *  @brief This function verify the received event pkt
 *
 *  Event format:
 *  +--------+--------+--------+--------+--------+
 *  | Event  | Length |  ncmd  |      Opcode     |
 *  +--------+--------+--------+--------+--------+
 *  | 1-byte | 1-byte | 1-byte |      2-byte     |
 *  +--------+--------+--------+--------+--------+
 *
 *  @param priv    A pointer to bt_private structure
 *  @param skb     A pointer to rx skb
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
check_evtpkt(bt_private *priv, struct sk_buff *skb)
{
	struct hci_event_hdr *hdr = (struct hci_event_hdr *)skb->data;
	struct hci_ev_cmd_complete *ec;
	u16 opcode, ocf;
	int ret = BT_STATUS_SUCCESS;
	ENTER();
	if (!priv->bt_dev.sendcmdflag) {
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	if (hdr->evt == HCI_EV_CMD_COMPLETE) {
		ec = (struct hci_ev_cmd_complete *)
			(skb->data + HCI_EVENT_HDR_SIZE);
		opcode = __le16_to_cpu(ec->opcode);
		ocf = hci_opcode_ocf(opcode);
		PRINTM(CMD,
		       "BT: CMD_COMPLTE opcode=0x%x, ocf=0x%x, send_cmd_opcode=0x%x\n",
		       opcode, ocf, priv->bt_dev.send_cmd_opcode);
		if (opcode != priv->bt_dev.send_cmd_opcode) {
			ret = BT_STATUS_FAILURE;
			goto exit;
		}
		switch (ocf) {
		case BT_CMD_MODULE_CFG_REQ:
		case BT_CMD_BLE_DEEP_SLEEP:
		case BT_CMD_CONFIG_MAC_ADDR:
		case BT_CMD_CSU_WRITE_REG:
		case BT_CMD_LOAD_CONFIG_DATA:
		case BT_CMD_LOAD_CONFIG_DATA_EXT:
		case BT_CMD_AUTO_SLEEP_MODE:
		case BT_CMD_HOST_SLEEP_CONFIG:
		case BT_CMD_SET_EVT_FILTER:
			// case BT_CMD_ENABLE_DEVICE_TESTMODE:
		case BT_CMD_PMIC_CONFIGURE:
		case BT_CMD_SET_GPIO_PIN:
		case BT_CMD_INDEPENDENT_RESET:
			priv->bt_dev.sendcmdflag = FALSE;
			priv->adapter->cmd_complete = TRUE;
			wake_up_interruptible(&priv->adapter->cmd_wait_q);
			break;
		case BT_CMD_GET_FW_VERSION:
			{
				u8 *pos = (skb->data + HCI_EVENT_HDR_SIZE +
					   sizeof(struct hci_ev_cmd_complete) +
					   1);

				u8 *hotfix_version =
					(skb->data + HCI_EVENT_HDR_SIZE +
					 sizeof(struct hci_ev_cmd_complete) +
					 1 + 8);

				if ((skb->len > 14) && (hotfix_version[0] != 0)) {
					snprintf(fw_version, sizeof(fw_version),
						 "%u.%u.%u.p%u.%u", pos[2],
						 pos[1], pos[0], pos[3],
						 hotfix_version[0]);
				} else {
					snprintf(fw_version, sizeof(fw_version),
						 "%u.%u.%u.p%u", pos[2], pos[1],
						 pos[0], pos[3]);
				}
				priv->bt_dev.sendcmdflag = FALSE;
				priv->adapter->cmd_complete = TRUE;
				wake_up_interruptible(&priv->adapter->
						      cmd_wait_q);
				break;
			}
		case BT_CMD_RESET:
		case BT_CMD_ENABLE_WRITE_SCAN:
			{
				priv->bt_dev.sendcmdflag = FALSE;
				priv->adapter->cmd_complete = TRUE;
				if (priv->adapter->wait_event_timeout == TRUE) {
					wake_up(&priv->adapter->cmd_wait_q);
					priv->adapter->wait_event_timeout =
						FALSE;
				} else
					wake_up_interruptible(&priv->adapter->
							      cmd_wait_q);
			}
			break;
		case BT_CMD_HOST_SLEEP_ENABLE:
			priv->bt_dev.sendcmdflag = FALSE;
			break;
		default:
			/** Ignore command not defined but send by driver */
			if (opcode == priv->bt_dev.send_cmd_opcode) {
				priv->bt_dev.sendcmdflag = FALSE;
				priv->adapter->cmd_complete = TRUE;
				wake_up_interruptible(&priv->adapter->
						      cmd_wait_q);
			} else {
				ret = BT_STATUS_FAILURE;
			}
			break;
		}
	} else
		ret = BT_STATUS_FAILURE;
exit:
	if (ret == BT_STATUS_SUCCESS)
		kfree_skb(skb);
	LEAVE();
	return ret;
}

/**
*  @brief This function stores the FW dumps received from events
*
*  @param priv    A pointer to bt_private structure
*  @param skb     A pointer to rx skb
*
*  @return        N/A
*/
void
bt_store_firmware_dump(bt_private *priv, u8 *buf, u32 len)
{
	struct file *pfile_fwdump = NULL;
	loff_t pos = 0;
	u16 seqnum = 0;
	bt_timeval t;
	u32 sec;

	ENTER();

	seqnum = __le16_to_cpu(*(u16 *) (buf + OFFSET_SEQNUM));

	if (priv->adapter->fwdump_fname && seqnum != 1) {
		pfile_fwdump =
			filp_open((const char *)priv->adapter->fwdump_fname,
				  O_CREAT | O_WRONLY | O_APPEND, 0644);
		if (IS_ERR(pfile_fwdump)) {
			PRINTM(MSG, "Cannot create firmware dump file.\n");
			LEAVE();
			return;
		}
	} else {
		if (!priv->adapter->fwdump_fname) {
			gfp_t flag;
			flag = (in_atomic() ||
				irqs_disabled())? GFP_ATOMIC : GFP_KERNEL;
			priv->adapter->fwdump_fname = kzalloc(64, flag);
		} else
			memset(priv->adapter->fwdump_fname, 0, 64);

		get_monotonic_time(&t);
		sec = (u32)t.time_sec;
		sprintf(priv->adapter->fwdump_fname, "%s%u",
			"/var/log/bt_fwdump_", sec);
		pfile_fwdump =
			filp_open(priv->adapter->fwdump_fname,
				  O_CREAT | O_WRONLY | O_APPEND, 0644);
		if (IS_ERR(pfile_fwdump)) {
			sprintf(priv->adapter->fwdump_fname, "%s%u",
				"/data/bt_fwdump_", sec);
			pfile_fwdump =
				filp_open((const char *)priv->adapter->
					  fwdump_fname,
					  O_CREAT | O_WRONLY | O_APPEND, 0644);
		}
	}

	if (IS_ERR(pfile_fwdump)) {
		PRINTM(MSG, "Cannot create firmware dump file\n");
		LEAVE();
		return;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	vfs_write(pfile_fwdump, buf, len, &pos);
#else
	kernel_write(pfile_fwdump, buf, len, &pos);
#endif
	filp_close(pfile_fwdump, NULL);
	LEAVE();
	return;
}

/**
 *  @brief This function process the received event
 *
 *  Event format:
 *  +--------+--------+--------+--------+-----+
 *  |   EC   | Length |           Data        |
 *  +--------+--------+--------+--------+-----+
 *  | 1-byte | 1-byte |          n-byte       |
 *  +--------+--------+--------+--------+-----+
 *
 *  @param priv    A pointer to bt_private structure
 *  @param skb     A pointer to rx skb
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_process_event(bt_private *priv, struct sk_buff *skb)
{
	int ret = BT_STATUS_SUCCESS;
#ifdef DEBUG_LEVEL1
	struct m_dev *m_dev = &(priv->bt_dev.m_dev[BT_SEQ]);
#endif
	BT_EVENT *pevent;

	ENTER();
	if (!m_dev) {
		PRINTM(CMD, "BT: bt_process_event without m_dev\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pevent = (BT_EVENT *)skb->data;
	if (pevent->EC != 0xff) {
		PRINTM(CMD, "BT: Not NXP Event=0x%x\n", pevent->EC);
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	switch (pevent->data[0]) {
	case BT_CMD_AUTO_SLEEP_MODE:
		if (pevent->data[2] == BT_STATUS_SUCCESS) {
			if (pevent->data[1] == BT_PS_ENABLE)
				priv->adapter->psmode = 1;
			else
				priv->adapter->psmode = 0;
			PRINTM(CMD, "BT: PS Mode %s:%s\n", m_dev->name,
			       (priv->adapter->psmode) ? "Enable" : "Disable");

		} else {
			PRINTM(CMD, "BT: PS Mode Command Fail %s\n",
			       m_dev->name);
		}
		break;
	case BT_CMD_HOST_SLEEP_CONFIG:
		if (pevent->data[3] == BT_STATUS_SUCCESS) {
			PRINTM(CMD, "BT: %s: gpio=0x%x, gap=0x%x\n",
			       m_dev->name, pevent->data[1], pevent->data[2]);
		} else {
			PRINTM(CMD, "BT: %s: HSCFG Command Fail\n",
			       m_dev->name);
		}
		break;
	case BT_CMD_HOST_SLEEP_ENABLE:
		if (pevent->data[1] == BT_STATUS_SUCCESS) {
			priv->adapter->hs_state = HS_ACTIVATED;
			if (priv->adapter->suspend_fail == FALSE) {
				if (priv->adapter->wait_event_timeout) {
					wake_up(&priv->adapter->cmd_wait_q);
					priv->adapter->wait_event_timeout =
						FALSE;
				} else
					wake_up_interruptible(&priv->adapter->
							      cmd_wait_q);

			}
			if (priv->adapter->psmode)
				priv->adapter->ps_state = PS_SLEEP;
			PRINTM(CMD, "BT: EVENT %s: HS ACTIVATED!\n",
			       m_dev->name);

		} else {
			PRINTM(CMD, "BT: %s: HS Enable Fail\n", m_dev->name);
		}
		break;
	case BT_CMD_MODULE_CFG_REQ:
		if ((priv->bt_dev.sendcmdflag == TRUE) &&
		    ((pevent->data[1] == MODULE_BRINGUP_REQ)
		     || (pevent->data[1] == MODULE_SHUTDOWN_REQ))) {
			if (pevent->data[1] == MODULE_BRINGUP_REQ) {
				PRINTM(CMD, "BT: EVENT %s:%s\n", m_dev->name,
				       (pevent->data[2] && (pevent->data[2] !=
							    MODULE_CFG_RESP_ALREADY_UP))
				       ? "Bring up Fail" : "Bring up success");
				priv->bt_dev.devType = pevent->data[3];
				PRINTM(CMD, "devType:%s\n",
				       (pevent->data[3] ==
					DEV_TYPE_AMP) ? "AMP controller" :
				       "BR/EDR controller");
				priv->bt_dev.devFeature = pevent->data[4];
				PRINTM(CMD, "devFeature:  %s,    %s,    %s"
				       "\n",
				       ((pevent->
					 data[4] & DEV_FEATURE_BT) ?
					"BT Feature" : "No BT Feature"),
				       ((pevent->
					 data[4] & DEV_FEATURE_BTAMP) ?
					"BTAMP Feature" : "No BTAMP Feature"),
				       ((pevent->
					 data[4] & DEV_FEATURE_BLE) ?
					"BLE Feature" : "No BLE Feature")
					);
			}
			if (pevent->data[1] == MODULE_SHUTDOWN_REQ) {
				PRINTM(CMD, "BT: EVENT %s:%s\n", m_dev->name,
				       (pevent->data[2]) ? "Shut down Fail"
				       : "Shut down success");

			}
			if (pevent->data[2]) {
				priv->bt_dev.sendcmdflag = FALSE;
				priv->adapter->cmd_complete = TRUE;
				wake_up_interruptible(&priv->adapter->
						      cmd_wait_q);
			}
		} else {
			PRINTM(CMD, "BT_CMD_MODULE_CFG_REQ resp for APP\n");
			ret = BT_STATUS_FAILURE;
		}
		break;
	case BT_EVENT_POWER_STATE:
		if (pevent->data[1] == BT_PS_SLEEP)
			priv->adapter->ps_state = PS_SLEEP;
		PRINTM(CMD, "BT: EVENT %s:%s\n", m_dev->name,
		       (priv->adapter->ps_state) ? "PS_SLEEP" : "PS_AWAKE");

		break;
	default:
		PRINTM(CMD, "BT: Unknown Event=%d %s\n", pevent->data[0],
		       m_dev->name);
		ret = BT_STATUS_FAILURE;
		break;
	}
exit:
	if (ret == BT_STATUS_SUCCESS)
		kfree_skb(skb);
	LEAVE();
	return ret;
}

/**
 *  @brief This function save the dump info to file
 *
 *
 *  @param dir_name     directory name
 *  @param file_name    file_name
 *  @return    0 --success otherwise fail
 */
int
bt_save_dump_info_to_file(char *dir_name, char *file_name, u8 *buf, u32 buf_len)
{
	int ret = BT_STATUS_SUCCESS;
	struct file *pfile = NULL;
	u8 name[64];
	loff_t pos;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	mm_segment_t fs;
#endif

	ENTER();

	if (!dir_name || !file_name || !buf) {
		PRINTM(ERROR, "Can't save dump info to file\n");
		ret = BT_STATUS_FAILURE;
		goto done;
	}

	memset(name, 0, sizeof(name));
	snprintf((char *)name, sizeof(name), "%s/%s", dir_name, file_name);
	pfile = filp_open((const char *)name, O_CREAT | O_RDWR, 0644);
	if (IS_ERR(pfile)) {
		PRINTM(MSG,
		       "Create file %s error, try to save dump file in /var\n",
		       name);
		memset(name, 0, sizeof(name));
		snprintf((char *)name, sizeof(name), "%s/%s", "/var",
			 file_name);
		pfile = filp_open((const char *)name, O_CREAT | O_RDWR, 0644);
	}
	if (IS_ERR(pfile)) {
		PRINTM(ERROR, "Create Dump file for %s error\n", name);
		ret = BT_STATUS_FAILURE;
		goto done;
	}

	PRINTM(MSG, "Dump data %s saved in %s\n", file_name, name);

	pos = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	fs = get_fs();
	set_fs(KERNEL_DS);
	vfs_write(pfile, (const char __user *)buf, buf_len, &pos);
	set_fs(fs);
#else
	kernel_write(pfile, (const char __user *)buf, buf_len, &pos);
#endif
	filp_close(pfile, NULL);

	PRINTM(MSG, "Dump data %s saved in %s successfully\n", file_name, name);

done:
	LEAVE();
	return ret;
}

/**
 *  @brief This function shows debug info for timeout of command sending.
 *
 *  @param adapter  A pointer to bt_private
 *  @param cmd      Timeout command id
 *
 *  @return         N/A
 */
static void
bt_cmd_timeout_func(bt_private *priv, u16 cmd)
{
	bt_adapter *adapter = priv->adapter;
	ENTER();

	adapter->num_cmd_timeout++;

	PRINTM(ERROR, "Version = %s\n", adapter->drv_ver);
	PRINTM(ERROR, "Timeout Command id = 0x%x\n", cmd);
	PRINTM(ERROR, "Number of command timeout = %d\n",
	       adapter->num_cmd_timeout);
	PRINTM(ERROR, "Interrupt counter = %d\n", adapter->IntCounter);
	PRINTM(ERROR, "Power Save mode = %d\n", adapter->psmode);
	PRINTM(ERROR, "Power Save state = %d\n", adapter->ps_state);
	PRINTM(ERROR, "Host Sleep state = %d\n", adapter->hs_state);
	PRINTM(ERROR, "hs skip count = %d\n", adapter->hs_skip);
	PRINTM(ERROR, "suspend_fail flag = %d\n", adapter->suspend_fail);
	PRINTM(ERROR, "suspended flag = %d\n", adapter->is_suspended);
	PRINTM(ERROR, "Number of wakeup tries = %d\n", adapter->WakeupTries);
	PRINTM(ERROR, "Host Cmd complet state = %d\n", adapter->cmd_complete);
	PRINTM(ERROR, "tx pending = %d\n", adapter->skb_pending);
	PRINTM(ERROR, "int status = %d\n", adapter->ireg);
	LEAVE();
}

/**
 *  @brief This function queue frame
 *
 *  @param priv	A pointer to bt_private structure
 *  @param skb	 A pointer to sk_buff structure
 *
 *  @return	N/A
 */
static void
bt_queue_frame(bt_private *priv, struct sk_buff *skb)
{
	skb_queue_tail(&priv->adapter->tx_queue, skb);
}

/**
 *  @brief This function send reset cmd to firmware
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return	       BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_send_reset_command(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_HCI_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_HCI_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_HCI_CMD *)skb->data;
	pcmd->ocf_ogf = __cpu_to_le16((RESET_OGF << 10) | BT_CMD_RESET);
	pcmd->length = 0x00;
	pcmd->cmd_type = 0x00;
	bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
	skb_put(skb, 3);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	PRINTM(CMD, "Queue Reset Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Reset timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_RESET);
	} else {
		PRINTM(CMD, "BT: Reset Command done\n");
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function sends module cfg cmd to firmware
 *
 *  Command format:
 *  +--------+--------+--------+--------+--------+--------+--------+
 *  |     OCF OGF     | Length |                Data               |
 *  +--------+--------+--------+--------+--------+--------+--------+
 *  |     2-byte      | 1-byte |               4-byte              |
 *  +--------+--------+--------+--------+--------+--------+--------+
 *
 *  @param priv    A pointer to bt_private structure
 *  @param subcmd  sub command
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_send_module_cfg_cmd(bt_private *priv, int subcmd)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "BT: No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_MODULE_CFG_REQ);
	pcmd->length = 1;
	pcmd->data[0] = subcmd;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	PRINTM(CMD, "Queue module cfg Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: module_cfg_cmd(%#x): timeout sendcmdflag=%d\n",
		       subcmd, priv->bt_dev.sendcmdflag);
		bt_cmd_timeout_func(priv, BT_CMD_MODULE_CFG_REQ);
	} else {
		PRINTM(CMD, "BT: module cfg Command done\n");
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function enables power save mode
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_enable_ps(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_AUTO_SLEEP_MODE);
	if (priv->bt_dev.psmode)
		pcmd->data[0] = BT_PS_ENABLE;
	else
		pcmd->data[0] = BT_PS_DISABLE;
	if (priv->bt_dev.idle_timeout) {
		pcmd->length = 3;
		pcmd->data[1] = (u8)(priv->bt_dev.idle_timeout & 0x00ff);
		pcmd->data[2] = (priv->bt_dev.idle_timeout & 0xff00) >> 8;
	} else {
		pcmd->length = 1;
	}
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue PSMODE Command(0x%x):%d\n",
	       __le16_to_cpu(pcmd->ocf_ogf), pcmd->data[0]);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: psmode timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_AUTO_SLEEP_MODE);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function sends hscfg command
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_send_hscfg_cmd(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_HOST_SLEEP_CONFIG);
	pcmd->length = 2;
	pcmd->data[0] = (priv->bt_dev.gpio_gap & 0xff00) >> 8;
	pcmd->data[1] = (u8)(priv->bt_dev.gpio_gap & 0x00ff);
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue HSCFG Command(0x%x),gpio=0x%x,gap=0x%x\n",
	       __le16_to_cpu(pcmd->ocf_ogf), pcmd->data[0], pcmd->data[1]);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: HSCFG timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_HOST_SLEEP_CONFIG);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function sends command to configure PMIC
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_pmic_configure(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();

	if (!(FALSE
#ifdef USB8997
	      || IS_USB8997(priv->adapter->card_type)
#endif
#ifdef USB8978
	      || IS_USB8978(priv->adapter->card_type)
#endif
#ifdef USB9098
	      || IS_USB9098(priv->adapter->card_type)
#endif
	      || IS_USB9097(priv->adapter->card_type)
#ifdef USBIW624
	      || IS_USBIW624(priv->adapter->card_type)
#endif
#ifdef USBIW610
	      || IS_USBIW610(priv->adapter->card_type)
#endif
	    )) {
		PRINTM(WARN,
		       "pmic configure not support on this card, skip it.\n");
		goto exit;
	}

	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_PMIC_CONFIGURE);
	pcmd->length = 0;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue PMIC Configure Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: PMIC Configure timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_PMIC_CONFIGURE);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function enables host sleep
 *
 *  @param priv    A pointer to bt_private structure
 *  @param is_shutdown  indicate shutdown mode
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_enable_hs(bt_private *priv, bool is_shutdown)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	priv->adapter->suspend_fail = FALSE;
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_HOST_SLEEP_ENABLE);
	pcmd->length = 0;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->adapter->wait_event_timeout = is_shutdown;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	PRINTM(CMD, "Queue hs enable Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (is_shutdown) {
		if (!os_wait_timeout
		    (priv->adapter->cmd_wait_q, priv->adapter->hs_state,
		     WAIT_UNTIL_HS_STATE_CHANGED)) {
			PRINTM(MSG, "BT: Enable host sleep timeout:\n");
			priv->adapter->wait_event_timeout = FALSE;
			bt_cmd_timeout_func(priv, BT_CMD_HOST_SLEEP_ENABLE);
		}
	} else {
		if (!os_wait_interruptible_timeout
		    (priv->adapter->cmd_wait_q, priv->adapter->hs_state,
		     WAIT_UNTIL_HS_STATE_CHANGED)) {
			PRINTM(MSG, "BT: Enable host sleep timeout:\n");
			bt_cmd_timeout_func(priv, BT_CMD_HOST_SLEEP_ENABLE);
		}
	}
	OS_INT_DISABLE;
	if ((priv->adapter->hs_state == HS_ACTIVATED) ||
	    (priv->adapter->is_suspended == TRUE)) {
		OS_INT_RESTORE;
		PRINTM(MSG, "BT: suspend success! skip=%d\n",
		       priv->adapter->hs_skip);
	} else {
		priv->adapter->suspend_fail = TRUE;
		OS_INT_RESTORE;
		priv->adapter->hs_skip++;
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG,
		       "BT: suspend skipped! "
		       "state=%d skip=%d ps_state= %d WakeupTries=%d\n",
		       priv->adapter->hs_state, priv->adapter->hs_skip,
		       priv->adapter->ps_state, priv->adapter->WakeupTries);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function Set Evt Filter
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_set_evt_filter(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf = __cpu_to_le16((0x03 << 10) | BT_CMD_SET_EVT_FILTER);
	pcmd->length = 0x03;
	pcmd->data[0] = 0x02;
	pcmd->data[1] = 0x00;
	pcmd->data[2] = 0x03;
	bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue Set Evt Filter Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Set Evt Filter timeout\n");
		bt_cmd_timeout_func(priv, BT_CMD_SET_EVT_FILTER);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function Enable Write Scan - Page and Inquiry
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_enable_write_scan(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf = __cpu_to_le16((0x03 << 10) | BT_CMD_ENABLE_WRITE_SCAN);
	pcmd->length = 0x01;
	pcmd->data[0] = 0x03;
	bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue Enable Write Scan Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Enable Write Scan timeout\n");
		bt_cmd_timeout_func(priv, BT_CMD_ENABLE_WRITE_SCAN);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function Enable Device under test mode
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_enable_device_under_testmode(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((0x06 << 10) | BT_CMD_ENABLE_DEVICE_TESTMODE);
	pcmd->length = 0x00;
	bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	PRINTM(CMD, "Queue enable device under testmode Command(0x%x)\n",
	       __le16_to_cpu(pcmd->ocf_ogf));
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Enable Device under TEST mode timeout\n");
		bt_cmd_timeout_func(priv, BT_CMD_ENABLE_DEVICE_TESTMODE);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function enables test mode and send cmd
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_enable_test_mode(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;

	ENTER();

	/** Set Evt Filter Command */
	ret = bt_set_evt_filter(priv);
	if (ret != BT_STATUS_SUCCESS) {
		PRINTM(ERROR, "BT test_mode: Set Evt filter fail\n");
		goto exit;
	}

				/** Enable Write Scan Command */
	ret = bt_enable_write_scan(priv);
	if (ret != BT_STATUS_SUCCESS) {
		PRINTM(ERROR, "BT test_mode: Enable Write Scan fail\n");
		goto exit;
	}

				/** Enable Device under test mode */
	ret = bt_enable_device_under_testmode(priv);
	if (ret != BT_STATUS_SUCCESS)
		PRINTM(ERROR,
		       "BT test_mode: Enable device under testmode fail\n");

exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function set GPIO pin
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_set_gpio_pin(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	/**Interrupt falling edge **/
	u8 gpio_int_edge = INT_FALLING_EDGE;
	/**Delay 50 usec **/
	u8 gpio_pulse_width = DELAY_50_US;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf = __cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_SET_GPIO_PIN);
	pcmd->data[0] = priv->adapter->params.mbt_gpio_pin;
	pcmd->data[1] = gpio_int_edge;
	pcmd->data[2] = gpio_pulse_width;
	pcmd->length = 3;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Set GPIO pin: timeout!\n");
		bt_cmd_timeout_func(priv, BT_CMD_SET_GPIO_PIN);
	}
exit:
	LEAVE();
	return ret;
}

#define DISABLE_RESET  0x0
#define ENABLE_OUTBAND_RESET 0x1
#define ENABLE_INBAND_RESET  0x02
#define DEFAULT_GPIO 0xff
/**
 *  @brief This function set GPIO pin
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_set_independent_reset(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	u8 mode, gpio;
	BT_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_INDEPENDENT_RESET);
	mode = priv->adapter->params.btindrst & 0xff;
	gpio = (priv->adapter->params.btindrst & 0xff00) >> 8;
	if (mode == ENABLE_OUTBAND_RESET) {
		pcmd->data[0] = ENABLE_OUTBAND_RESET;
		if (!gpio)
			pcmd->data[1] = DEFAULT_GPIO;
		else
			pcmd->data[1] = gpio;
	} else if (mode == ENABLE_INBAND_RESET) {
		pcmd->data[0] = ENABLE_INBAND_RESET;
		pcmd->data[1] = DEFAULT_GPIO;
	} else if (mode == DISABLE_RESET) {
		pcmd->data[0] = DISABLE_RESET;
		pcmd->data[1] = DEFAULT_GPIO;
	} else {
		PRINTM(WARN, "Unsupport mode\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	PRINTM(CMD, "BT: independant reset mode=%d gpio=%d\n", mode, gpio);
	pcmd->length = 2;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Independent reset : timeout!\n");
		bt_cmd_timeout_func(priv, BT_CMD_INDEPENDENT_RESET);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function sets ble deepsleep mode
 *
 *  @param priv    A pointer to bt_private structure
 *  @param mode    TRUE/FALSE
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_set_ble_deepsleep(bt_private *priv, int mode)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_BLE_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_BLE_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_BLE_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_BLE_DEEP_SLEEP);
	pcmd->length = 1;
	pcmd->deepsleep = mode;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, sizeof(BT_BLE_CMD));
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	PRINTM(CMD, "BT: Set BLE deepsleep = %d (0x%x)\n", mode,
	       __le16_to_cpu(pcmd->ocf_ogf));
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Set BLE deepsleep timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_BLE_DEEP_SLEEP);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function gets FW version
 *
 *  @param priv    A pointer to bt_private structure
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_get_fw_version(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_HCI_CMD *pcmd;
	ENTER();

	if (bt_extflg_isset(priv, EXT_BT_BLOCK_CMD))
		goto exit;

	skb = bt_skb_alloc(sizeof(BT_HCI_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_HCI_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_GET_FW_VERSION);
	pcmd->length = 0x01;
	pcmd->cmd_type = 0x00;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, 4);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout(priv->adapter->cmd_wait_q,
					   priv->adapter->cmd_complete,
					   WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Get FW version: timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_GET_FW_VERSION);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function sets mac address
 *
 *  @param priv    A pointer to bt_private structure
 *  @param mac     A pointer to mac address
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_set_mac_address(bt_private *priv, u8 *mac)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_HCI_CMD *pcmd;
	int i = 0;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_HCI_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_HCI_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_CONFIG_MAC_ADDR);
	pcmd->length = 8;
	pcmd->cmd_type = MRVL_VENDOR_PKT;
	pcmd->cmd_len = 6;
	for (i = 0; i < 6; i++)
		pcmd->data[i] = mac[5 - i];
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, sizeof(BT_HCI_CMD));
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	PRINTM(CMD, "BT: Set mac addr " MACSTR " (0x%x)\n", MAC2STR(mac),
	       __le16_to_cpu(pcmd->ocf_ogf));
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(MSG, "BT: Set mac addr: timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_CONFIG_MAC_ADDR);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function load the calibrate EXT data
 *
 *  @param priv    A pointer to bt_private structure
 *  @param config_data     A pointer to calibrate data
 *  @param mac     A pointer to mac address
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_process_commands(bt_private *priv, u8 *cmd_data, u32 cmd_len)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	u16 ogf = 0;

	ENTER();
	PRINTM(CMD, "BT: init cmds: len=%d\n", cmd_len);
	if (cmd_len > BT_CMD_DATA_LEN) {
		PRINTM(WARN, "cfg_data_len is too long exceed %d.\n",
		       BT_CMD_DATA_LEN);
		ret = BT_STATUS_FAILURE;
		goto exit;
	}

	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	memcpy(skb->data, cmd_data, cmd_len);
	pcmd = (BT_CMD *)skb->data;

	ogf = hci_opcode_ogf(pcmd->ocf_ogf);
	if (ogf == VENDOR_OGF)
		bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	else
		bt_cb(skb)->pkt_type = HCI_COMMAND_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;

	DBG_HEXDUMP(DAT_D, "init_cmds", skb->data, skb->len);
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(ERROR, "BT: Load init cmds: timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_LOAD_CONFIG_DATA_EXT);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function load the calibrate data
 *
 *  @param priv    A pointer to bt_private structure
 *  @param config_data     A pointer to calibrate data
 *  @param mac     A pointer to mac address
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_load_cal_data(bt_private *priv, u8 *config_data, u8 *mac)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;
	int i = 0;
	/* u8 config_data[28] = {0x37 0x01 0x1c 0x00 0xFF 0xFF 0xFF 0xFF 0x01
	   0x7f 0x04 0x02 0x00 0x00 0xBA 0xCE 0xC0 0xC6 0x2D 0x00 0x00 0x00
	   0x00 0x00 0x00 0x00 0xF0}; */

	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_LOAD_CONFIG_DATA);
	pcmd->length = 0x20;
	pcmd->data[0] = 0x00;
	pcmd->data[1] = 0x00;
	pcmd->data[2] = 0x00;
	pcmd->data[3] = 0x1C;
	/* swip cal-data byte */
	for (i = 4; i < 32; i++)
		pcmd->data[i] = *(config_data + ((i / 4) * 8 - 1 - i));
	if (mac != NULL) {
		pcmd->data[2] = 0x01;	/* skip checksum */
		for (i = 24; i < 30; i++)
			pcmd->data[i] = mac[29 - i];
	}
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;

	DBG_HEXDUMP(DAT_D, "calirate data: ", pcmd->data, 32);
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(ERROR, "BT: Load calibrate data: timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_LOAD_CONFIG_DATA);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function load the calibrate EXT data
 *
 *  @param priv    A pointer to bt_private structure
 *  @param config_data     A pointer to calibrate data
 *  @param mac     A pointer to mac address
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_load_cal_data_ext(bt_private *priv, u8 *config_data, u32 cfg_data_len,
		     int cfg_ext2)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CMD *pcmd;

	ENTER();

	if (cfg_data_len > BT_CMD_DATA_LEN) {
		PRINTM(WARN, "cfg_data_len is too long exceed %d.\n",
		       BT_CMD_DATA_LEN);
		ret = BT_STATUS_FAILURE;
		goto exit;
	}

	skb = bt_skb_alloc(sizeof(BT_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CMD *)skb->data;
	pcmd->ocf_ogf = __cpu_to_le16((VENDOR_OGF << 10) |
				      (cfg_ext2 ?
				       HCI_CMD_MARVELL_STORE_CAL_DATA_ANNEX_100
				       : BT_CMD_LOAD_CONFIG_DATA_EXT));
	pcmd->length = cfg_data_len;

	memcpy(pcmd->data, config_data, cfg_data_len);
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, BT_CMD_HEADER_SIZE + pcmd->length);
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;

	DBG_HEXDUMP(DAT_D, "calirate ext data", pcmd->data, pcmd->length);
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(ERROR, "BT: Load calibrate ext data: timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_LOAD_CONFIG_DATA_EXT);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function writes value to CSU registers
 *
 *  @param priv    A pointer to bt_private structure
 *  @param type    reg type
 *  @param offset  register address
 *  @param value   register value to write
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_write_reg(bt_private *priv, u8 type, u32 offset, u16 value)
{
	struct sk_buff *skb = NULL;
	int ret = BT_STATUS_SUCCESS;
	BT_CSU_CMD *pcmd;
	ENTER();
	skb = bt_skb_alloc(sizeof(BT_CSU_CMD), GFP_ATOMIC);
	if (skb == NULL) {
		PRINTM(WARN, "No free skb\n");
		ret = BT_STATUS_FAILURE;
		goto exit;
	}
	pcmd = (BT_CSU_CMD *)skb->data;
	pcmd->ocf_ogf =
		__cpu_to_le16((VENDOR_OGF << 10) | BT_CMD_CSU_WRITE_REG);
	pcmd->length = 7;
	pcmd->type = type;
	pcmd->offset[0] = (offset & 0x000000ff);
	pcmd->offset[1] = (offset & 0x0000ff00) >> 8;
	pcmd->offset[2] = (offset & 0x00ff0000) >> 16;
	pcmd->offset[3] = (offset & 0xff000000) >> 24;
	pcmd->value[0] = (value & 0x00ff);
	pcmd->value[1] = (value & 0xff00) >> 8;
	bt_cb(skb)->pkt_type = MRVL_VENDOR_PKT;
	skb_put(skb, sizeof(BT_CSU_CMD));
	skb->dev = (void *)(&(priv->bt_dev.m_dev[BT_SEQ]));
	skb_queue_head(&priv->adapter->tx_queue, skb);
	priv->bt_dev.sendcmdflag = TRUE;
	priv->bt_dev.send_cmd_opcode = __le16_to_cpu(pcmd->ocf_ogf);
	priv->adapter->cmd_complete = FALSE;
	PRINTM(CMD, "BT: Set CSU reg type=%d reg=0x%x value=0x%x\n",
	       type, offset, value);
	wake_up_interruptible(&priv->MainThread.waitQ);
	if (!os_wait_interruptible_timeout
	    (priv->adapter->cmd_wait_q, priv->adapter->cmd_complete,
	     WAIT_UNTIL_CMD_RESP)) {
		ret = BT_STATUS_FAILURE;
		PRINTM(ERROR, "BT: Set CSU reg timeout:\n");
		bt_cmd_timeout_func(priv, BT_CMD_CSU_WRITE_REG);
	}
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief This function used to restore tx_queue
 *
 *  @param priv    A pointer to bt_private structure
 *  @return        N/A
 */
void
bt_restore_tx_queue(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	while (!skb_queue_empty(&priv->adapter->pending_queue)) {
		skb = skb_dequeue(&priv->adapter->pending_queue);
		if (skb)
			bt_queue_frame(priv, skb);
	}
	wake_up_interruptible(&priv->MainThread.waitQ);
}

/**
 *  @brief This function used to send command to firmware
 *
 *  Command format:
 *  +--------+--------+--------+--------+--------+--------+--------+
 *  |     OCF OGF     | Length |                Data               |
 *  +--------+--------+--------+--------+--------+--------+--------+
 *  |     2-byte      | 1-byte |               4-byte              |
 *  +--------+--------+--------+--------+--------+--------+--------+
 *
 *  @param priv    A pointer to bt_private structure
 *  @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_prepare_command(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	ENTER();
	if (priv->bt_dev.hscfgcmd) {
		priv->bt_dev.hscfgcmd = 0;
		ret = bt_send_hscfg_cmd(priv);
	}
	if (priv->bt_dev.pscmd) {
		priv->bt_dev.pscmd = 0;
		ret = bt_enable_ps(priv);
	}
	if (priv->bt_dev.hscmd) {
		priv->bt_dev.hscmd = 0;
		if (priv->bt_dev.hsmode)
			ret = bt_enable_hs(priv, FALSE);
		else {
			ret = priv->adapter->ops.wakeup_firmware(priv);
			priv->adapter->hs_state = HS_DEACTIVATED;
		}
	}
	if (priv->bt_dev.test_mode) {
		priv->bt_dev.test_mode = 0;
		ret = bt_enable_test_mode(priv);
	}
	LEAVE();
	return ret;
}

static void
update_stat_byte_tx(bt_private *priv, struct sk_buff *skb)
{
	((struct hci_dev *)priv->bt_dev.m_dev[BT_SEQ].dev_pointer)->stat.
		byte_tx += skb->len;
}

static void
update_stat_err_tx(bt_private *priv, struct sk_buff *skb)
{
	((struct hci_dev *)priv->bt_dev.m_dev[BT_SEQ].dev_pointer)->stat.
		err_tx++;
}

/** @brief This function processes a single packet
 *
 *  @param priv    A pointer to bt_private structure
 *  @param skb     A pointer to skb which includes TX packet
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
send_single_packet(bt_private *priv, struct sk_buff *skb)
{
	int ret;

	ENTER();
	if (!skb || !skb->data) {
		LEAVE();
		return BT_STATUS_FAILURE;
	}
	ret = priv->adapter->ops.host_to_card(priv, skb);
	if (ret == BT_STATUS_FAILURE)
		update_stat_err_tx(priv, skb);
	else
		update_stat_byte_tx(priv, skb);
	if (ret != BT_STATUS_PENDING)
		kfree_skb(skb);
	LEAVE();
	return ret;
}

/**
 *  @brief This function initializes the adapter structure
 *  and set default value to the member of adapter.
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    N/A
 */
static int
bt_init_adapter(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;

	ENTER();

	skb_queue_head_init(&priv->adapter->tx_queue);
	skb_queue_head_init(&priv->adapter->pending_queue);
	priv->adapter->tx_lock = FALSE;
	priv->adapter->ps_state = PS_AWAKE;
	priv->adapter->suspend_fail = FALSE;
	priv->adapter->is_suspended = FALSE;
	priv->adapter->hs_skip = 0;
	priv->adapter->num_cmd_timeout = 0;
	priv->adapter->fwdump_fname = NULL;
	init_waitqueue_head(&priv->adapter->cmd_wait_q);
	priv->adapter->ireg = 0;
	return ret;
	LEAVE();
}

/**
 *  @brief This function initializes firmware
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
bt_init_fw(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if (priv->adapter->ops.download_fw(priv)) {
		PRINTM(ERROR, " FW failed to be download!\n");
		ret = BT_STATUS_FAILURE;
		goto done;
	}
done:
	LEAVE();
	return ret;
}

/**
 *  @brief This function request to reload firmware
 *
 *  @param priv   A pointer to bt_private
 *  @param mode   fw reload mode.
 *
 *  @return         N/A
 */
void
bt_request_fw_reload(bt_private *priv, int mode)
{
	ENTER();
	if (mode == FW_RELOAD_WITH_EMULATION) {
		bt_fw_reload = FW_RELOAD_WITH_EMULATION;
		PRINTM(MSG, "BT: FW reload with re-emulation...\n");
		LEAVE();
		return;
	}
	LEAVE();
	return;
}

/**
 *  @brief This function frees the structure of adapter
 *
 *  @param priv    A pointer to bt_private structure
 *  @return    N/A
 */
void
bt_free_adapter(bt_private *priv)
{
	bt_adapter *adapter = priv->adapter;
	ENTER();
	skb_queue_purge(&priv->adapter->tx_queue);
	skb_queue_purge(&adapter->pending_queue);
	adapter->tx_lock = FALSE;
	/* Free allocated memory for fwdump filename */
	if (adapter->fwdump_fname) {
		kfree(adapter->fwdump_fname);
		adapter->fwdump_fname = NULL;
	}
	bt_free_module_param(priv);
	/* Free the adapter object itself */
	kfree(adapter);
	priv->adapter = NULL;

	LEAVE();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
/**
 *  @brief This function handles the BT ioctl
 *
 *  @param hdev     A pointer to hci_dev structure
 *  @cmd            ioctl cmd
 *  @arg            argument
 *  @return    -ENOIOCTLCMD
 */
static int
bt_ioctl(struct hci_dev *hdev, unsigned int cmd, unsigned long arg)
{
	ENTER();
	LEAVE();
	return -ENOIOCTLCMD;
}
#endif

/**
 *  @brief This function handles the wrapper_dev ioctl
 *
 *  @param hev     A pointer to wrapper_dev structure
 *  @cmd            ioctl cmd
 *  @arg            argument
 *  @return    -ENOIOCTLCMD
 */
static int
mdev_ioctl(struct m_dev *m_dev, unsigned int cmd, void *arg)
{
	bt_private *priv = NULL;
	int ret = 0;

	ENTER();

	if (!m_dev || !m_dev->driver_data) {
		PRINTM(ERROR, "Ioctl for unknown device (m_dev=NULL)\n");
		ret = -ENODEV;
		goto done;
	}
	priv = (bt_private *)m_dev->driver_data;
	if (!test_bit(HCI_RUNNING, &m_dev->flags)) {
		PRINTM(ERROR, "HCI_RUNNING not set, flag=0x%lx\n",
		       m_dev->flags);
		ret = -EBUSY;
		goto done;
	}
	PRINTM(INFO, "IOCTL: cmd=%d\n", cmd);
	switch (cmd) {

	case MBTCHAR_IOCTL_BT_FW_DUMP:
		break;

	default:
		break;
	}

done:
	LEAVE();
	return ret;
}

/**
 *  @brief This function handles BT destruct
 *
 *  @param hdev    A pointer to hci_dev structure
 *
 *  @return    N/A
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
static void
bt_destruct(struct hci_dev *hdev)
{
	ENTER();
	LEAVE();
	return;
}
#endif

/**
 *  @brief This function handles wrapper device destruct
 *
 *  @param m_dev   A pointer to m_dev structure
 *
 *  @return    N/A
 */
static void
mdev_destruct(struct m_dev *m_dev)
{
	ENTER();
	LEAVE();
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
/**
 *  @brief This function handles the BT transmit
 *
 *  @param skb     A pointer to sk_buff structure
 *
 *  @return    BT_STATUS_SUCCESS or other error no.
 */
static int
bt_send_frame(struct sk_buff *skb)
#else
/**
 *  @brief This function handles the BT transmit
 *
 *  @param hdev    A pointer to hci_dev structure
 *  @param skb     A pointer to sk_buff structure
 *
 *  @return    BT_STATUS_SUCCESS or other error no.
 */
static int
bt_send_frame(struct hci_dev *hdev, struct sk_buff *skb)
#endif
{
	bt_private *priv = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	struct hci_dev *hdev = (struct hci_dev *)skb->dev;
#else
	skb->dev = (void *)hdev;
#endif

	ENTER();
	PRINTM(DATA, "bt_send_frame %s: Type=%d, len=%d\n", hdev->name,
	       bt_cb(skb)->pkt_type, skb->len);
	DBG_HEXDUMP(CMD_D, "bt_send_frame", skb->data, skb->len);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	if (!hdev || !hci_get_drvdata(hdev)) {
#else
	if (!hdev || !hdev->driver_data) {
#endif
		PRINTM(ERROR, "Frame for unknown HCI device (hdev=NULL)\n");
		LEAVE();
		return -ENODEV;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	priv = (bt_private *)hci_get_drvdata(hdev);
#else
	priv = (bt_private *)hdev->driver_data;
#endif
	if (bt_extflg_isset(priv, EXT_BT_BLOCK_CMD)) {
		kfree_skb(skb);
		LEAVE();
		return BT_STATUS_SUCCESS;
	}
	if (!test_bit(HCI_RUNNING, &hdev->flags)) {
		PRINTM(ERROR, "Fail test HCI_RUNNING, flag=0x%lx\n",
		       hdev->flags);
		LEAVE();
		return -EBUSY;
	}
	switch (bt_cb(skb)->pkt_type) {
	case HCI_COMMAND_PKT:
		hdev->stat.cmd_tx++;
		break;
	case HCI_ACLDATA_PKT:
		hdev->stat.acl_tx++;
		break;
	case HCI_SCODATA_PKT:
		hdev->stat.sco_tx++;
		break;
	}
	if (priv->adapter->tx_lock == TRUE)
		skb_queue_tail(&priv->adapter->pending_queue, skb);
	else
		bt_queue_frame(priv, skb);

	wake_up_interruptible(&priv->MainThread.waitQ);
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function handles the wrapper device transmit
 *
 *  @param m_dev   A pointer to m_dev structure
 *  @param skb     A pointer to sk_buff structure
 *
 *  @return    BT_STATUS_SUCCESS or other error no.
 */
static int
mdev_send_frame(struct m_dev *m_dev, struct sk_buff *skb)
{
	bt_private *priv = NULL;

	ENTER();
	if (!m_dev || !m_dev->driver_data) {
		PRINTM(ERROR, "Frame for unknown HCI device (m_dev=NULL)\n");
		LEAVE();
		return -ENODEV;
	}
	priv = (bt_private *)m_dev->driver_data;
	if (!test_bit(HCI_RUNNING, &m_dev->flags)) {
		PRINTM(ERROR, "Fail test HCI_RUNNING, flag=0x%lx\n",
		       m_dev->flags);
		LEAVE();
		return -EBUSY;
	}
	switch (bt_cb(skb)->pkt_type) {
	case HCI_COMMAND_PKT:
		m_dev->stat.cmd_tx++;
		break;
	case HCI_ACLDATA_PKT:
		m_dev->stat.acl_tx++;
		break;
	case HCI_SCODATA_PKT:
		m_dev->stat.sco_tx++;
		break;
	}

	if (priv->adapter->tx_lock == TRUE)
		skb_queue_tail(&priv->adapter->pending_queue, skb);
	else
		bt_queue_frame(priv, skb);
	wake_up_interruptible(&priv->MainThread.waitQ);

	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function flushes the transmit queue
 *
 *  @param hdev     A pointer to hci_dev structure
 *
 *  @return    BT_STATUS_SUCCESS
 */
static int
bt_flush(struct hci_dev *hdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	bt_private *priv = (bt_private *)hci_get_drvdata(hdev);
#else
	bt_private *priv = (bt_private *)hdev->driver_data;
#endif
	ENTER();
	skb_queue_purge(&priv->adapter->tx_queue);
	skb_queue_purge(&priv->adapter->pending_queue);
#ifdef USB
	if (IS_USB(priv->adapter->card_type))
		usb_flush(priv);
#endif
	LEAVE();
	return BT_STATUS_SUCCESS;
}

#ifdef USB_SCO_SUPPORT
static void
bt_notify(struct hci_dev *hdev, unsigned int evt)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	bt_private *priv = (bt_private *)hci_get_drvdata(hdev);
#else
	bt_private *priv = (bt_private *)hdev->driver_data;
#endif
	ENTER();
	usb_notify(priv, evt);
	LEAVE();
}
#endif /* USB_SCO_SUPPORT */

/**
 *  @brief This function flushes the transmit queue
 *
 *  @param m_dev     A pointer to m_dev structure
 *
 *  @return    BT_STATUS_SUCCESS
 */
static int
mdev_flush(struct m_dev *m_dev)
{
	bt_private *priv = (bt_private *)m_dev->driver_data;
	ENTER();
	skb_queue_purge(&priv->adapter->tx_queue);
	skb_queue_purge(&priv->adapter->pending_queue);
#ifdef USB
	if (IS_USB(priv->adapter->card_type))
		usb_flush(priv);
#endif
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function closes the bluetooth device
 *
 *  @param hdev    A pointer to hci_dev structure
 *
 *  @return    BT_STATUS_SUCCESS
 */
static int
bt_close(struct hci_dev *hdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	bt_private *priv = (bt_private *)hci_get_drvdata(hdev);
#else
	bt_private *priv = (bt_private *)hdev->driver_data;
#endif

	ENTER();
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
	if (!test_and_clear_bit(HCI_RUNNING, &hdev->flags)) {
		LEAVE();
		return BT_STATUS_SUCCESS;
	}
#endif
	skb_queue_purge(&priv->adapter->tx_queue);
#ifdef USB
	if (IS_USB(priv->adapter->card_type))
		usb_free_frags(priv);
#endif

	module_put(THIS_MODULE);
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function closes the wrapper device
 *
 *  @param m_dev   A pointer to m_dev structure
 *
 *  @return    BT_STATUS_SUCCESS
 */
static int
mdev_close(struct m_dev *m_dev)
{
#ifdef USB
	bt_private *priv = (bt_private *)m_dev->driver_data;
#endif

	ENTER();
	mdev_req_lock(m_dev);
	if (!test_and_clear_bit(HCI_UP, &m_dev->flags)) {
		mdev_req_unlock(m_dev);
		LEAVE();
		return 0;
	}

	if (m_dev->flush)
		m_dev->flush(m_dev);
	/* wait up pending read and unregister char dev */
	wake_up_interruptible(&m_dev->req_wait_q);
	/* Drop queues */
	skb_queue_purge(&m_dev->rx_q);
#ifdef USB
	if (IS_USB(priv->adapter->card_type))
		usb_free_frags(priv);
#endif
	if (!test_and_clear_bit(HCI_RUNNING, &m_dev->flags)) {
		mdev_req_unlock(m_dev);
		LEAVE();
		return 0;
	}
	module_put(THIS_MODULE);
	m_dev->flags = 0;
	mdev_req_unlock(m_dev);
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function opens the bluetooth device
 *
 *  @param hdev    A pointer to hci_dev structure
 *
 *  @return    BT_STATUS_SUCCESS  or other
 */
static int
bt_open(struct hci_dev *hdev)
{
	ENTER();
	if (try_module_get(THIS_MODULE) == 0)
		return BT_STATUS_FAILURE;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
	set_bit(HCI_RUNNING, &hdev->flags);
#endif
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function opens the wrapper device
 *
 *  @param m_dev   A pointer to m_dev structure
 *
 *  @return    BT_STATUS_SUCCESS  or other
 */
static int
mdev_open(struct m_dev *m_dev)
{
	ENTER();

	if (try_module_get(THIS_MODULE) == 0)
		return BT_STATUS_FAILURE;

	set_bit(HCI_RUNNING, &m_dev->flags);

	LEAVE();
	return BT_STATUS_SUCCESS;
}

#ifdef USB
#ifdef USB_SCO_SUPPORT
/**
 *  @brief This function notify BT sco connection for USB char device
 *
 *  @param m_dev        A pointer to m_dev structure
 *  @param arg  arguement
 *
 *  @return     BT_STATUS_SUCCESS  or other
 */
static void
mdev_notify(struct m_dev *m_dev, unsigned int arg)
{
	bt_private *priv = NULL;
	ENTER();

	if (!m_dev || !m_dev->driver_data) {
		PRINTM(ERROR, "Frame for unknown HCI device (m_dev=NULL)\n");
		LEAVE();
		return;
	}
	priv = (bt_private *)m_dev->driver_data;
	if (!test_bit(HCI_RUNNING, &m_dev->flags)) {
		PRINTM(ERROR, "Fail test HCI_RUNNING, flag=0x%lx\n",
		       m_dev->flags);
		LEAVE();
		return;
	}
	usb_char_notify(priv, arg);

	LEAVE();
}
#endif
#endif

/**
 *  @brief This function queries the wrapper device
 *
 *  @param m_dev   A pointer to m_dev structure
 *  @param arg     arguement
 *
 *  @return    BT_STATUS_SUCCESS  or other
 */
void
mdev_query(struct m_dev *m_dev, void *arg)
{
	struct mbt_dev *mbt_dev = (struct mbt_dev *)m_dev->dev_pointer;

	ENTER();
	if (copy_to_user(arg, &mbt_dev->type, sizeof(mbt_dev->type)))
		PRINTM(ERROR, "IOCTL_QUERY_TYPE: Fail copy to user\n");

	LEAVE();
}

/**
 *  @brief This function initializes the wrapper device
 *
 *  @param priv   A pointer to bt_private structure
 *  @param m_dev   A pointer to m_dev structure
 *
 *  @return    BT_STATUS_SUCCESS  or other
 */
void
init_m_dev(bt_private *priv, struct m_dev *m_dev)
{
	m_dev->dev_pointer = NULL;
	m_dev->driver_data = NULL;
	m_dev->dev_type = 0;
	m_dev->spec_type = 0;
	skb_queue_head_init(&m_dev->rx_q);
	init_waitqueue_head(&m_dev->req_wait_q);
	init_waitqueue_head(&m_dev->rx_wait_q);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
	init_MUTEX(&m_dev->req_lock);
#else
	sema_init(&m_dev->req_lock, 1);
#endif
	spin_lock_init(&m_dev->rxlock);
	memset(&m_dev->stat, 0, sizeof(struct hci_dev_stats));
	m_dev->open = mdev_open;
	m_dev->close = mdev_close;
	m_dev->flush = mdev_flush;
	m_dev->send = mdev_send_frame;
	m_dev->destruct = mdev_destruct;
#ifdef USB
#ifdef USB_SCO_SUPPORT
	if (IS_USB(priv->adapter->card_type))
		m_dev->notify = mdev_notify;
#endif
#endif
	m_dev->ioctl = mdev_ioctl;
	m_dev->query = mdev_query;
	m_dev->owner = THIS_MODULE;

}

/**
 *  @brief This function handles the major job in bluetooth driver.
 *  it handles the event generated by firmware, rx data received
 *  from firmware and tx data sent from kernel.
 *
 *  @param data    A pointer to bt_thread structure
 *  @return        BT_STATUS_SUCCESS
 */
static int
bt_service_main_thread(void *data)
{
	bt_thread *thread = data;
	bt_private *priv = thread->priv;
	bt_adapter *adapter = priv->adapter;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
	wait_queue_t wait;
#else
	wait_queue_entry_t wait;
#endif
	struct sk_buff *skb;
	ENTER();
	bt_activate_thread(thread);
	init_waitqueue_entry(&wait, current);
	current->flags |= PF_NOFREEZE;

	for (;;) {
		add_wait_queue(&thread->waitQ, &wait);
		OS_SET_THREAD_STATE(TASK_INTERRUPTIBLE);
		if (priv->adapter->WakeupTries ||
		    ((!priv->adapter->IntCounter) &&
		     (!priv->bt_dev.tx_dnld_rdy ||
		      skb_queue_empty(&priv->adapter->tx_queue))
		    )) {
			PRINTM(INFO, "Main: Thread sleeping...\n");
			schedule();
		}
		OS_SET_THREAD_STATE(TASK_RUNNING);
		remove_wait_queue(&thread->waitQ, &wait);
		if (kthread_should_stop() || priv->SurpriseRemoved) {
			PRINTM(INFO, "main-thread: break from main thread: "
			       "SurpriseRemoved=0x%x\n", priv->SurpriseRemoved);
			break;
		}

		PRINTM(INFO, "Main: Thread waking up...\n");

		if (priv->adapter->IntCounter) {
			OS_INT_DISABLE;
			adapter->IntCounter = 0;
			OS_INT_RESTORE;
			if (priv->adapter->ops.get_int_status)
				priv->adapter->ops.get_int_status(priv);
		} else if ((priv->adapter->ps_state == PS_SLEEP) &&
			   (!skb_queue_empty(&priv->adapter->tx_queue)
			   )) {
			priv->adapter->WakeupTries++;
			priv->adapter->ops.wakeup_firmware(priv);
			continue;
		}
		if (priv->adapter->ps_state == PS_SLEEP)
			continue;
		if (priv->bt_dev.tx_dnld_rdy == TRUE) {
			if (!skb_queue_empty(&priv->adapter->tx_queue)) {
				skb = skb_dequeue(&priv->adapter->tx_queue);
				if (skb)
					send_single_packet(priv, skb);
			}
		}
	}
	bt_deactivate_thread(thread);
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function handles the interrupt. it will change PS
 *  state if applicable. it will wake up main_thread to handle
 *  the interrupt event as well.
 *
 *  @param m_dev   A pointer to m_dev structure
 *  @return        N/A
 */
void
bt_interrupt(struct m_dev *m_dev)
{
	bt_private *priv = (bt_private *)m_dev->driver_data;
	ENTER();
	if (!priv || !priv->adapter) {
		LEAVE();
		return;
	}
	PRINTM(INTR, "*\n");
	priv->adapter->ps_state = PS_AWAKE;
	if (priv->adapter->hs_state == HS_ACTIVATED) {
		PRINTM(CMD, "BT: %s: HS DEACTIVATED in ISR!\n", m_dev->name);
		priv->adapter->hs_state = HS_DEACTIVATED;
	}
	priv->adapter->WakeupTries = 0;
	priv->adapter->IntCounter++;
	wake_up_interruptible(&priv->MainThread.waitQ);
	LEAVE();
}

static void
bt_private_dynamic_release(struct kobject *kobj)
{
	bt_private *priv = container_of(kobj, bt_private, kobj);
	ENTER();
	PRINTM(INFO, "free bt priv\n");
	kfree(priv);
	LEAVE();
}

static struct kobj_type ktype_bt_private_dynamic = {
	.release = bt_private_dynamic_release,
};

static bt_private *
bt_alloc_priv(void)
{
	bt_private *priv;
	ENTER();
	priv = kzalloc(sizeof(bt_private), GFP_KERNEL);
	if (priv) {
		kobject_init(&priv->kobj, &ktype_bt_private_dynamic);
		PRINTM(INFO, "alloc bt priv\n");
	}
	LEAVE();
	return priv;
}

struct kobject *
bt_priv_get(bt_private *priv)
{
	PRINTM(INFO, "bt priv get object");
	return kobject_get(&priv->kobj);
}

void
bt_priv_put(bt_private *priv)
{
	PRINTM(INFO, "bt priv put object");
	kobject_put(&priv->kobj);
}

/**
 *  @brief This function send init commands to firmware
 *
 *  @param priv   A pointer to bt_private structure
 *  @return       BT_STATUS_SUCESS/BT_STATUS_FAILURE
 */
int
bt_init_cmd(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;

	ENTER();

	if (bt_extflg_isset(priv, EXT_BT_BLOCK_CMD))
		goto done;
	if (priv->adapter->params.mbt_gpio_pin) {
		ret = bt_set_gpio_pin(priv);
		if (ret < 0) {
			PRINTM(FATAL, "GPIO pin set failed!\n");
			goto done;
		}
	}
	ret = bt_send_module_cfg_cmd(priv, MODULE_BRINGUP_REQ);
	if (ret < 0) {
		PRINTM(FATAL, "Module cfg command send failed!\n");
		goto done;
	}
	if (priv->adapter->params.btindrst != -1) {
		ret = bt_set_independent_reset(priv);
		if (ret < 0) {
			PRINTM(FATAL, "Independent reset failed!\n");
			goto done;
		}
	}
	if (bt_extflg_isset(priv, EXT_BTPMIC)) {
		if (BT_STATUS_SUCCESS != bt_pmic_configure(priv)) {
			PRINTM(FATAL, "BT: PMIC Configure failed \n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	ret = bt_set_ble_deepsleep(priv, bt_extflg_isset(priv, EXT_DEEP_SLEEP));
	if (ret < 0) {
		PRINTM(FATAL, "%s BLE deepsleep failed!\n",
		       bt_extflg_isset(priv,
				       EXT_DEEP_SLEEP) ? "Enable" : "Disable");
		goto done;
	}
	if (bt_extflg_isset(priv, EXT_PSMODE)) {
		priv->bt_dev.psmode = TRUE;
		priv->bt_dev.idle_timeout = DEFAULT_IDLE_TIME;
		ret = bt_enable_ps(priv);
		if (ret < 0) {
			PRINTM(FATAL, "Enable PS mode failed!\n");
			goto done;
		}
	}
	priv->bt_dev.gpio_gap = DEF_GPIO_GAP;
	ret = bt_send_hscfg_cmd(priv);
	if (ret < 0) {
		PRINTM(FATAL, "Send HSCFG failed!\n");
		goto done;
	}
	wake_up_interruptible(&priv->MainThread.waitQ);

done:
	LEAVE();
	return ret;
}

/**
 *  @brief Module configuration and register device
 *
 *  @param priv      A Pointer to bt_private structure
 *  @return      BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
sbi_register_conf_dpc(bt_private *priv)
{
	int ret = BT_STATUS_SUCCESS;
	struct hci_dev *hdev = NULL;
	unsigned char dev_type = 0;
	char *init_cfg = NULL, *cal_cfg = NULL, *bt_mac = NULL, *cal_cfg_ext =
		NULL;
	char *cal_cfg_ext2 = NULL;
	char *init_cmds = NULL;
	int drv_mode = priv->adapter->params.drv_mode;

	ENTER();

	priv->bt_dev.tx_dnld_rdy = TRUE;

	if (drv_mode & DRV_MODE_BT) {
		hdev = hci_alloc_dev();
		if (!hdev) {
			PRINTM(FATAL, "Can not allocate HCI device\n");
			ret = -ENOMEM;
			goto err_kmalloc;
		}
		hdev->open = bt_open;
		hdev->close = bt_close;
		hdev->flush = bt_flush;
		hdev->send = bt_send_frame;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
		hdev->destruct = bt_destruct;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
		hdev->ioctl = bt_ioctl;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
		hci_set_drvdata(hdev, priv);
#else
		hdev->driver_data = priv;
#endif

#ifdef USB_SCO_SUPPORT
		if (IS_USB(priv->adapter->card_type))
			hdev->notify = bt_notify;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)
		hdev->owner = THIS_MODULE;
#endif
		init_m_dev(priv, &(priv->bt_dev.m_dev[BT_SEQ]));
		priv->bt_dev.m_dev[BT_SEQ].dev_type = BT_TYPE;
		priv->bt_dev.m_dev[BT_SEQ].spec_type = BLUEZ_SPEC;
		priv->bt_dev.m_dev[BT_SEQ].dev_pointer = (void *)hdev;
		priv->bt_dev.m_dev[BT_SEQ].driver_data = priv;
	}

	if (IS_USB(priv->adapter->card_type))
		dev_type = HCI_USB;
	else if (IS_SD(priv->adapter->card_type))
		dev_type = HCI_SDIO;
	else if (IS_PCIE(priv->adapter->card_type))
		dev_type = HCI_PCI;
	else {
		PRINTM(FATAL, "Invalid card type: %x\n",
		       priv->adapter->card_type);
		ret = -EFAULT;
		goto err_kmalloc;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
	if (hdev)
		hdev->bus = dev_type;
#else
	if (hdev)
		hdev->type = dev_type;
#endif /* >= 2.6.34 */

	ret = bt_init_cmd(priv);
	if (ret < 0) {
		PRINTM(FATAL, "BT init command failed!\n");
		goto done;
	}

	init_cmds = priv->adapter->params.init_cmds;
	init_cfg = priv->adapter->params.init_cfg;
	cal_cfg = priv->adapter->params.cal_cfg;
	bt_mac = priv->adapter->params.bt_mac;
	cal_cfg_ext = priv->adapter->params.cal_cfg_ext;
	cal_cfg_ext2 = priv->adapter->params.cal_cfg_ext2;
	/** Process device tree init parameters before register hci device.
	 *  Since uplayer device has not yet registered, no need to block tx queue.
	 * */
	if (init_cfg) {
		if (BT_STATUS_SUCCESS != bt_init_config(priv, init_cfg)) {
			PRINTM(FATAL,
			       "BT: Set user init data and param failed\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	if (cal_cfg) {
		if (BT_STATUS_SUCCESS != bt_cal_config(priv, cal_cfg, bt_mac)) {
			PRINTM(FATAL, "BT: Set cal data failed\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	} else if (bt_mac) {
		PRINTM(INFO,
		       "Set BT mac_addr from insmod parametre bt_mac = %s\n",
		       bt_mac);
		if (BT_STATUS_SUCCESS != bt_init_mac_address(priv, bt_mac)) {
			PRINTM(FATAL,
			       "BT: Fail to set mac address from insmod parametre\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	if (cal_cfg_ext) {
		if (BT_STATUS_SUCCESS !=
		    bt_cal_config_ext(priv, cal_cfg_ext, 0)) {
			PRINTM(FATAL, "BT: Set cal ext data failed\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}

	if (cal_cfg_ext2) {
		if (BT_STATUS_SUCCESS !=
		    bt_cal_config_ext(priv, cal_cfg_ext2, 1)) {
			PRINTM(FATAL, "BT: Set cal ext2 data failed\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	if (init_cmds) {
		if (BT_STATUS_SUCCESS != bt_init_cmds(priv, init_cmds)) {
			PRINTM(FATAL, "BT: Set user init commands failed\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}

	/* Get FW version */
	bt_get_fw_version(priv);
	snprintf((char *)priv->adapter->drv_ver, MAX_VER_STR_LEN,
		 mbt_driver_version, fw_version);

	if (hdev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 6, 32)
		hdev->dev_type = priv->bt_dev.devType;
#endif
#endif
		ret = hci_register_dev(hdev);
		if (ret < 0) {
			PRINTM(FATAL, "Can not register HCI device\n");
			ret = BT_STATUS_FAILURE;
			goto done;
		}
		snprintf((char *)priv->bt_dev.m_dev[BT_SEQ].name,
			 sizeof(priv->bt_dev.m_dev[BT_SEQ].name), hdev->name);
		bt_proc_init(priv, &(priv->bt_dev.m_dev[BT_SEQ]), BT_SEQ);
	}

done:
	LEAVE();
	return ret;
err_kmalloc:
	LEAVE();
	return ret;
}

/**
 *  @brief This function adds the card. it will probe the
 *  card, allocate the bt_priv and initialize the device.
 *
 *  @param card    A pointer to card
 *  @return        A pointer to bt_private structure
 */

bt_private *
bt_add_card(void *card, struct device *dev, bt_if_ops * ops, u16 card_type)
{
	bt_private *priv = NULL;
	int index = 0;

	ENTER();

	priv = bt_alloc_priv();
	if (!priv) {
		PRINTM(FATAL, "Can not allocate priv\n");
		LEAVE();
		return NULL;
	}
	/* Save the handle */
	for (index = 0; index < MAX_BT_ADAPTER; index++) {
		if (m_priv[index] == NULL)
			break;
	}
	if (index < MAX_BT_ADAPTER) {
		m_priv[index] = priv;
	} else {
		PRINTM(ERROR, "Exceeded maximum cards supported!\n");
		goto err_kmalloc;
	}
	/* allocate buffer for bt_adapter */
	priv->adapter = kzalloc(sizeof(bt_adapter), GFP_KERNEL);
	if (!priv->adapter) {
		PRINTM(FATAL, "Allocate buffer for bt_adapter failed!\n");
		goto err_kmalloc;
	}

	priv->adapter->card_type = card_type;
	PRINTM(MSG, "Attach interface ops, type: 0x%x\n", card_type);
	memcpy(&priv->adapter->ops, ops, sizeof(*ops));
	bt_init_module_param(dev, priv);

	if (BT_STATUS_SUCCESS != priv->adapter->ops.get_device(priv))
		goto err_kmalloc;

	if (bt_init_adapter(priv) != BT_STATUS_SUCCESS)
		goto err_kmalloc;

	PRINTM(INFO, "Starting kthread...\n");
	priv->MainThread.priv = priv;
	spin_lock_init(&priv->driver_lock);

	bt_create_thread(bt_service_main_thread, &priv->MainThread,
			 "bt_main_service");

	/* wait for mainthread to up */
	while (!priv->MainThread.pid)
		os_sched_timeout(1);

	/** user config file */
	init_waitqueue_head(&priv->init_user_conf_wait_q);

	priv->bt_dev.card = card;

	/*
	 * Register the device. Fillup the private data structure with
	 * relevant information from the card and request for the required
	 * IRQ.
	 */
	if (priv->adapter->ops.register_dev(priv) < 0) {
		PRINTM(FATAL, "Failed to register bt device!\n");
		goto err_registerdev;
	}
	if (bt_init_fw(priv)) {
		PRINTM(FATAL, "BT Firmware Init Failed\n");
		goto err_init_fw;
	}
	LEAVE();
	return priv;

err_init_fw:
	clean_up_m_devs(priv);
	bt_proc_remove(priv);
	PRINTM(INFO, "Unregister device\n");
	priv->adapter->ops.unregister_dev(priv);
err_registerdev:
	/* Stop the thread servicing the interrupts */
	priv->SurpriseRemoved = TRUE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	while (priv->MainThread.pid)
		os_sched_timeout(1);
err_kmalloc:
	if (priv->adapter)
		bt_free_adapter(priv);
	for (index = 0; index < MAX_BT_ADAPTER; index++) {
		if (m_priv[index] == priv) {
			m_priv[index] = NULL;
			break;
		}
	}
	bt_priv_put(priv);
	LEAVE();
	return NULL;
}

/**
 *  @brief This function send hardware remove event
 *
 *  @param priv    A pointer to bt_private
 *  @return        N/A
 */
void
bt_send_hw_remove_event(bt_private *priv)
{
	struct sk_buff *skb = NULL;
	struct hci_dev *hdev = NULL;
	ENTER();
	if (!priv->bt_dev.m_dev[BT_SEQ].dev_pointer) {
		LEAVE();
		return;
	}
	if (priv->bt_dev.m_dev[BT_SEQ].spec_type == BLUEZ_SPEC)
		hdev = (struct hci_dev *)priv->bt_dev.m_dev[BT_SEQ].dev_pointer;
#define HCI_HARDWARE_ERROR_EVT  0x10
#define HCI_HARDWARE_REMOVE     0x24
	skb = bt_skb_alloc(3, GFP_ATOMIC);
	skb->data[0] = HCI_HARDWARE_ERROR_EVT;
	skb->data[1] = 1;
	skb->data[2] = HCI_HARDWARE_REMOVE;
	bt_cb(skb)->pkt_type = HCI_EVENT_PKT;
	skb_put(skb, 3);
	if (hdev) {
		skb->dev = (void *)hdev;
		PRINTM(MSG, "Send HW ERROR event\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
		hci_recv_frame(skb);
#else
		hci_recv_frame(hdev, skb);
#endif
		os_sched_timeout(5);
		hdev->stat.byte_rx += 3;
	}
	LEAVE();
	return;
}

/**
 *  @brief This function removes the card.
 *
 *  @param card    A pointer to card
 *  @return        BT_STATUS_SUCCESS
 */
int
bt_remove_card(void *card)
{
	bt_private *priv = (bt_private *)card;
	int index;
	ENTER();
	if (!priv) {
		LEAVE();
		return BT_STATUS_SUCCESS;
	}
	priv->SurpriseRemoved = TRUE;
	bt_send_hw_remove_event(priv);
	wake_up_interruptible(&priv->adapter->cmd_wait_q);
	priv->SurpriseRemoved = TRUE;
	wake_up_interruptible(&priv->MainThread.waitQ);
	while (priv->MainThread.pid) {
		os_sched_timeout(1);
		wake_up_interruptible(&priv->MainThread.waitQ);
	}

	bt_proc_remove(priv);
	PRINTM(INFO, "Unregister device\n");
	priv->adapter->ops.unregister_dev(priv);
	clean_up_m_devs(priv);
	PRINTM(INFO, "Free Adapter\n");
	bt_free_adapter(priv);
	for (index = 0; index < MAX_BT_ADAPTER; index++) {
		if (m_priv[index] == priv) {
			m_priv[index] = NULL;
			break;
		}
	}
	bt_priv_put(priv);
	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief This function initializes module.
 *
 *  @return    BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
bt_init_module(void)
{
	int ret = BT_STATUS_SUCCESS;
	int index;
	ENTER();
	PRINTM(MSG, "BT: Loading driver\n");
	/* Init the bt_private pointer array first */
	for (index = 0; index < MAX_BT_ADAPTER; index++)
		m_priv[index] = NULL;
	bt_root_proc_init();

	/** create char device class */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 3, 13)
	chardev_class = class_create(THIS_MODULE, MODULE_NAME);
#else
	chardev_class = class_create(MODULE_NAME);
#endif
	if (IS_ERR(chardev_class)) {
		PRINTM(ERROR, "Unable to allocate class\n");
		ret = PTR_ERR(chardev_class);
		goto done;
	}

#ifdef USB
	if (sbi_usb_register() == NULL) {
		ret = BT_STATUS_FAILURE;
		goto done;
	}
#endif
done:
	if (ret) {
		bt_root_proc_remove();
		PRINTM(MSG, "BT: Driver loading failed\n");
	} else {
		PRINTM(MSG, "BT: Driver loaded successfully\n");
	}
	LEAVE();
	return ret;
}

/**
 *  @brief This function cleans module
 *
 *  @return        N/A
 */
static void
bt_exit_module(void)
{
	bt_private *priv;
	int index;
	ENTER();
	PRINTM(MSG, "BT: Unloading driver\n");
	for (index = 0; index < MAX_BT_ADAPTER; index++) {
		priv = m_priv[index];
		if (!priv)
			continue;
		if (priv && !priv->SurpriseRemoved) {
			if (BT_STATUS_SUCCESS == bt_send_reset_command(priv))
				bt_send_module_cfg_cmd(priv,
						       MODULE_SHUTDOWN_REQ);
		}
	}
#ifdef USB
	sbi_usb_unregister();
#endif
	bt_root_proc_remove();
	class_destroy(chardev_class);
	PRINTM(MSG, "BT: Driver unloaded\n");
	LEAVE();
}

module_init(bt_init_module);
module_exit(bt_exit_module);

MODULE_AUTHOR("NXP");
MODULE_DESCRIPTION("NXP Bluetooth Driver Ver. " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
