/** @file bt_init.c
  *
  * @brief This file contains the init functions for BlueTooth
  * driver.
  *
  *
  * Copyright 2014-2021, 2024 NXP
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

#include <linux/string.h>
#include <linux/firmware.h>
#ifdef CONFIG_OF
#include <linux/of.h>
#endif

#include "bt_drv.h"

#undef isxdigit
#define isxdigit(c)    (('0' <= (c) && (c) <= '9') \
                        || ('a' <= (c) && (c) <= 'f') \
                        || ('A' <= (c) && (c) <= 'F'))

#undef isdigit
#define isdigit(c)     (('0' <= (c) && (c) <= '9'))
#undef isspace
#define isspace(c)  (c <= ' ' && (c == ' ' || (c <= 13 && c >= 9)))
/********************************************************
                Global Variables
********************************************************/
extern bt_private *m_priv[];

/** Default Driver mode */
static int drv_mode = (DRV_MODE_BT);

/** fw reload flag */
int bt_fw_reload;
/** fw serial download flag */
int bt_fw_serial = 1;

/** module parameter file name */
char *bt_mod_para;
/** Firmware flag */
static int fw = 1;
/** default powermode */
static int psmode = 1;
/** default BLE deep sleep */
static int deep_sleep = 1;
/** Init config file (MAC address, register etc.) */
static char *init_cfg;
/** Calibration config file (MAC address, init powe etc.) */
static char *cal_cfg;
/** Calibration config file EXT */
static char *cal_cfg_ext;
/** Calibration config file EXT support Annex_100/101*/
static char *cal_cfg_ext2;
/** Init MAC address */
static char *bt_mac;
/** init cmds file */
static char *init_cmds;
static int mbt_gpio_pin;
static int btindrst = -1;

/** Setting mbt_drvdbg value based on DEBUG level */
#ifdef DEBUG_LEVEL1
#ifdef DEBUG_LEVEL2
#define DEFAULT_DEBUG_MASK  (0xffffffff & ~DBG_EVENT)
#else
#define DEFAULT_DEBUG_MASK  (DBG_MSG | DBG_FATAL | DBG_ERROR)
#endif /* DEBUG_LEVEL2 */
u32 mbt_drvdbg = DEFAULT_DEBUG_MASK;
#endif

#ifdef CONFIG_OF
static int dts_enable = 1;
#endif

#if defined(SD8997) || defined(USB8997) || defined(SD8977) || defined(SD9098)|| defined(SDIW624)||defined(SDIW610) \
||defined(SD9097)||defined(USB9098)||defined(PCIE9098)||defined(USBIW624)||defined(USBIW610)||defined(USB9097) \
||defined(SD8978)||defined(USB8978) || defined(SD9177)
static int btpmic = 0;
#endif

int bt_req_fw_nowait;

/** Firmware name */
char *fw_name;

static card_type_entry card_type_map_tbl[] = {
#ifdef USB8897
	{CARD_TYPE_USB8897, 0, CARD_USB8897},
#endif
#ifdef USB8997
	{CARD_TYPE_USB8997, 0, CARD_USB8997},
#endif
#ifdef USB8978
	{CARD_TYPE_USB8978, 0, CARD_USB8978},
#endif
#ifdef USB9098
	{CARD_TYPE_USB9098, 0, CARD_USB9098},
	{CARD_TYPE_PCIEUSB9098, 0, CARD_USB9098},
#endif
#ifdef USBIW624
	{CARD_TYPE_USBIW624, 0, CARD_USBIW624},
#endif
#ifdef USBIW610
	{CARD_TYPE_USBIW610, 0, CARD_USBIW610},
#endif
	{CARD_TYPE_USB9097, 0, CARD_USB9097},
	{CARD_TYPE_PCIEUSB9097, 0, CARD_USB9097},
};

/**
 *  @brief Returns hex value of a give character
 *
 *  @param chr	Character to be converted
 *
 *  @return	The converted character if chr is a valid hex, else 0
 */
static int
bt_hexval(char chr)
{
	ENTER();

	if (chr >= '0' && chr <= '9')
		return chr - '0';
	if (chr >= 'A' && chr <= 'F')
		return chr - 'A' + 10;
	if (chr >= 'a' && chr <= 'f')
		return chr - 'a' + 10;

	LEAVE();
	return 0;
}

/**
 *  @brief Extension of strsep lib command. This function will also take care
 *	   escape character
 *
 *  @param s         A pointer to array of chars to process
 *  @param delim     The delimiter character to end the string
 *  @param esc       The escape character to ignore for delimiter
 *
 *  @return          Pointer to the separated string if delim found, else NULL
 */
static char *
bt_strsep(char **s, char delim, char esc)
{
	char *se = *s, *sb;

	ENTER();

	if (!(*s) || (*se == '\0')) {
		LEAVE();
		return NULL;
	}

	for (sb = *s; *sb != '\0'; ++sb) {
		if (*sb == esc && *(sb + 1) == esc) {
			/*
			 * We get a esc + esc seq then keep the one esc
			 * and chop off the other esc character
			 */
			memmove(sb, sb + 1, strlen(sb));
			continue;
		}
		if (*sb == esc && *(sb + 1) == delim) {
			/*
			 * We get a delim + esc seq then keep the delim
			 * and chop off the esc character
			 */
			memmove(sb, sb + 1, strlen(sb));
			continue;
		}
		if (*sb == delim)
			break;
	}

	if (*sb == '\0')
		sb = NULL;
	else
		*sb++ = '\0';

	*s = sb;

	LEAVE();
	return se;
}

/**
 *  @brief Returns hex value of a given ascii string
 *
 *  @param a	String to be converted
 *
 *  @return	hex value
 */
static int
bt_atox(const char *a)
{
	int i = 0;
	ENTER();
	while (isxdigit(*a))
		i = i * 16 + bt_hexval(*a++);

	LEAVE();
	return i;
}

/**
 *  @brief Converts mac address from string to t_u8 buffer.
 *
 *  @param mac_addr The buffer to store the mac address in.
 *  @param buf      The source of mac address which is a string.
 *
 *  @return	N/A
 */
static void
bt_mac2u8(u8 *mac_addr, char *buf)
{
	char *begin, *end, *mac_buff;
	int i;

	ENTER();

	if (!buf) {
		LEAVE();
		return;
	}

	mac_buff = kzalloc(strlen(buf) + 1, GFP_KERNEL);
	if (!mac_buff) {
		LEAVE();
		return;
	}
	memcpy(mac_buff, buf, strlen(buf));

	begin = mac_buff;
	for (i = 0; i < ETH_ALEN; ++i) {
		end = bt_strsep(&begin, ':', '/');
		if (end)
			mac_addr[i] = bt_atox(end);
	}

	kfree(mac_buff);
	LEAVE();
}

/**
 *  @brief Returns integer value of a given ascii string
 *
 *  @param data    Converted data to be returned
 *  @param a       String to be converted
 *
 *  @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
bt_atoi(int *data, char *a)
{
	int i, val = 0, len;

	ENTER();

	len = strlen(a);
	if (!strncmp(a, "0x", 2)) {
		a = a + 2;
		len -= 2;
		*data = bt_atox(a);
		return BT_STATUS_SUCCESS;
	}
	for (i = 0; i < len; i++) {
		if (isdigit(a[i])) {
			val = val * 10 + (a[i] - '0');
		} else {
			PRINTM(ERROR, "Invalid char %c in string %s\n", a[i],
			       a);
			return BT_STATUS_FAILURE;
		}
	}
	*data = val;

	LEAVE();
	return BT_STATUS_SUCCESS;
}

/**
 *  @brief parse cal-data
 *
 *  @param src      a pointer to cal-data string
 *  @param len      len of cal-data
 *  @param dst      a pointer to return cal-data
 *  @param dst_size size of dest buffer
 *
 *  @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
static int
bt_parse_cal_cfg(const u8 *src, u32 len, u8 *dst, u32 *dst_size)
{
	const u8 *ptr;
	u8 *dptr;
	u32 count = 0;
	int ret = BT_STATUS_FAILURE;

	ENTER();
	ptr = src;
	dptr = dst;

	while ((ptr - src) < len) {
		if (*ptr && isspace(*ptr)) {
			ptr++;
			continue;
		}

		if (isxdigit(*ptr)) {
			if ((dptr - dst) >= *dst_size) {
				PRINTM(ERROR, "cal_file size too big!!!\n");
				goto done;
			}
			*dptr++ = bt_atox((const char *)ptr);
			ptr += 2;
			count++;
		} else {
			ptr++;
		}
	}
	if (dptr == dst) {
		ret = BT_STATUS_FAILURE;
		goto done;
	}

	*dst_size = count;
	ret = BT_STATUS_SUCCESS;
done:
	LEAVE();
	return ret;
}

/**
 *    @brief parse ASCII format raw data to hex format
 *
 *    @param priv         bt_private
 *    @param data         Source data
 *    @param size         Source data length
 *    @return             MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int
bt_process_init_raw_cmds(bt_private *priv, u8 *data, u32 size)
{
	int ret = 0;
	u8 *pos = data;
	u8 *intf_s, *intf_e;
	u8 *buf = NULL;
	u8 *ptr = NULL;
	u8 cmd_len = 0;
	bool start_raw = false;
	gfp_t flag;

	flag = (in_atomic() || irqs_disabled())? GFP_ATOMIC : GFP_KERNEL;
	buf = kzalloc(MRVDRV_SIZE_OF_CMD_BUFFER, flag);

	if (!buf) {
		PRINTM(ERROR, "Could not allocate buffer space!\n");
		return -EFAULT;
	}
	ptr = buf;
	while ((pos - data) < size) {
		while ((*pos == ' ' || *pos == '\t') && ((pos - data) < size))
			pos++;
		if (*pos == '#') {	/* Line comment */
			while ((*pos != '\n') && ((pos - data) < size))
				pos++;
			pos++;
		}
		if ((*pos == '\r' && *(pos + 1) == '\n') || *pos == '\n' ||
		    *pos == '\0') {
			pos++;
			continue;	/* Needn't process this line */
		}

		if (*pos == '}') {
			/* For hostcmd data conf */
			cmd_len = *(buf + sizeof(u16));
			ret = bt_process_commands(priv, buf,
						  cmd_len + BT_CMD_HEADER_SIZE);
			memset(buf, 0, MRVDRV_SIZE_OF_CMD_BUFFER);
			ptr = buf;
			start_raw = false;
			pos++;
			continue;
		}

		if (start_raw == false) {
			intf_s = strchr(pos, '=');
			if (intf_s)
				intf_e = strchr(intf_s, '{');
			else
				intf_e = NULL;

			if (intf_s && intf_e) {
				start_raw = true;
				pos = intf_e + 1;
				continue;
			}
		}

		if (start_raw) {
			/* Raw data block exists */
			while (*pos != '\n' && ((pos - data) < size)) {
				if (isxdigit(*pos)) {
					if ((ptr - buf) <
					    MRVDRV_SIZE_OF_CMD_BUFFER)
						*ptr++ = bt_atox(pos);
					pos += 2;
				} else
					pos++;
			}
		}
	}
	kfree(buf);
	return ret;
}

/**
 *    @brief BT set user init commands
 *
 *    @param priv     BT private handle
 *    @param init_cmds_file user init commands file
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */

int
bt_init_cmds(bt_private *priv, char *init_cmds_file)
{
	const struct firmware *cfg = NULL;
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if ((request_firmware(&cfg, init_cmds_file, priv->hotplug_device)) < 0) {
		PRINTM(FATAL, "BT: request_firmware() %s failed\n",
		       init_cmds_file);
		ret = BT_STATUS_FAILURE;
		goto done;
	}
	if (cfg)
		ret = bt_process_init_raw_cmds(priv, (u8 *)cfg->data,
					       cfg->size);
	else
		ret = BT_STATUS_FAILURE;
done:
	if (cfg)
		release_firmware(cfg);
	LEAVE();
	return ret;
}

/**
 *    @brief BT get one line data from ASCII format data
 *
 *    @param data         Source data
 *    @param size         Source data length
 *    @param line_pos     Destination data
 *    @return             -1 or length of the line
 */
int
parse_cfg_get_line(u8 *data, u32 size, u8 *line_pos)
{
	static s32 pos;
	u8 *src, *dest;

	if (pos >= size) {	/* reach the end */
		pos = 0;	/* Reset position for rfkill */
		return -1;
	}
	memset(line_pos, 0, MAX_LINE_LEN);
	src = data + pos;
	dest = line_pos;

	while ((dest - line_pos < MAX_LINE_LEN - 1) && pos < size &&
	       *src != '\x0A' && *src != '\0') {
		if (*src != ' ' && *src != '\t')	/* parse space */
			*dest++ = *src++;
		else
			src++;
		pos++;
	}
	*dest = '\0';
	/* parse new line */
	pos++;
	return strlen((const char *)line_pos);
}

/**
 *    @brief BT parse ASCII format data to MAC address
 *
 *    @param priv          BT private handle
 *    @param data          Source data
 *    @param size          data length
 *    @return              BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_process_init_cfg(bt_private *priv, u8 *data, u32 size)
{
	u8 *pos;
	u8 *intf_s, *intf_e;
	u8 s[MAX_LINE_LEN];	/* 1 line data */
	u32 line_len;
	char dev_name[MAX_PARAM_LEN];
	u8 buf[MAX_PARAM_LEN];
	u8 bt_addr[MAX_MAC_ADDR_LEN];
	u8 bt_mac[ETH_ALEN];
	int setting = 0;
	u8 type = 0;
	u16 value = 0;
	u32 offset = 0;
	int ret = BT_STATUS_FAILURE;

	memset(dev_name, 0, sizeof(dev_name));
	memset(bt_addr, 0, sizeof(bt_addr));
	memset(bt_mac, 0, sizeof(bt_mac));

	while ((line_len = parse_cfg_get_line(data, size, s)) != -1) {
		pos = s;
		while (*pos == ' ' || *pos == '\t')
			pos++;

		if (*pos == '#' || (*pos == '\r' && *(pos + 1) == '\n') ||
		    *pos == '\n' || *pos == '\0')
			continue;	/* Need n't process this line */

		/* Process MAC addr */
		if (strncmp((char *)pos, "mac_addr", 8) == 0) {
			intf_s = (u8 *)strchr((const char *)pos, '=');
			if (intf_s != NULL)
				intf_e = (u8 *)strchr((const char *)intf_s,
						      ':');
			else
				intf_e = NULL;
			if (intf_s != NULL && intf_e != NULL) {
				if ((intf_e - intf_s) > MAX_PARAM_LEN) {
					PRINTM(ERROR,
					       "BT: Too long interface name %d\n",
					       __LINE__);
					goto done;
				}
				strncpy(dev_name, (const char *)intf_s + 1,
					intf_e - intf_s - 1);
				dev_name[intf_e - intf_s - 1] = '\0';
				strncpy((char *)bt_addr,
					(const char *)intf_e + 1,
					MAX_MAC_ADDR_LEN - 1);
				bt_addr[MAX_MAC_ADDR_LEN - 1] = '\0';
				/* Convert MAC format */
				bt_mac2u8(bt_mac, (char *)bt_addr);
				PRINTM(CMD,
				       "HCI: %s new BT Address " MACSTR "\n",
				       dev_name, MAC2STR(bt_mac));
				if (BT_STATUS_SUCCESS !=
				    bt_set_mac_address(priv, bt_mac)) {
					PRINTM(FATAL,
					       "BT: Fail to set mac address\n");
					goto done;
				}
			} else {
				PRINTM(ERROR,
				       "BT: Wrong config file format %d\n",
				       __LINE__);
				goto done;
			}
		}
		/* Process REG value */
		else if (strncmp((char *)pos, "bt_reg", 6) == 0) {
			intf_s = (u8 *)strchr((const char *)pos, '=');
			if (intf_s != NULL)
				intf_e = (u8 *)strchr((const char *)intf_s,
						      ',');
			else
				intf_e = NULL;
			if (intf_s != NULL && intf_e != NULL) {
				/* Copy type */
				memset(buf, 0, sizeof(buf));
				strncpy((char *)buf, (const char *)intf_s + 1,
					1);
				buf[1] = '\0';
				if (0 == bt_atoi(&setting, (char *)buf))
					type = (u8)setting;
				else {
					PRINTM(ERROR,
					       "BT: Fail to parse reg type\n");
					goto done;
				}
			} else {
				PRINTM(ERROR,
				       "BT: Wrong config file format %d\n",
				       __LINE__);
				goto done;
			}
			intf_s = intf_e + 1;
			intf_e = (u8 *)strchr((const char *)intf_s, ',');
			if (intf_e != NULL) {
				if ((intf_e - intf_s) >= MAX_PARAM_LEN) {
					PRINTM(ERROR,
					       "BT: Regsier offset is too long %d\n",
					       __LINE__);
					goto done;
				}
				/* Copy offset */
				memset(buf, 0, sizeof(buf));
				strncpy((char *)buf, (const char *)intf_s,
					intf_e - intf_s);
				buf[intf_e - intf_s] = '\0';
				if (0 == bt_atoi(&setting, (char *)buf))
					offset = (u32)setting;
				else {
					PRINTM(ERROR,
					       "BT: Fail to parse reg offset\n");
					goto done;
				}
			} else {
				PRINTM(ERROR,
				       "BT: Wrong config file format %d\n",
				       __LINE__);
				goto done;
			}
			intf_s = intf_e + 1;
			if ((strlen((const char *)intf_s) >= MAX_PARAM_LEN)) {
				PRINTM(ERROR,
				       "BT: Regsier value is too long %d\n",
				       __LINE__);
				goto done;
			}
			/* Copy value */
			memset(buf, 0, sizeof(buf));
			strncpy((char *)buf, (const char *)intf_s, sizeof(buf));
			if (0 == bt_atoi(&setting, (char *)buf))
				value = (u16) setting;
			else {
				PRINTM(ERROR, "BT: Fail to parse reg value\n");
				goto done;
			}

			PRINTM(CMD,
			       "BT: Write reg type: %d offset: 0x%x value: 0x%x\n",
			       type, offset, value);
			if (BT_STATUS_SUCCESS !=
			    bt_write_reg(priv, type, offset, value)) {
				PRINTM(FATAL,
				       "BT: Write reg failed. type: %d offset: 0x%x value: 0x%x\n",
				       type, offset, value);
				goto done;
			}
		}
	}
	ret = BT_STATUS_SUCCESS;

done:
	LEAVE();
	return ret;
}

/**
 * @brief BT request init conf firmware callback
 *        This function is invoked by request_firmware_nowait system call
 *
 * @param firmware  A pointer to firmware image
 * @param context   A pointer to bt_private structure
 *
 * @return          N/A
 */
static void
bt_request_init_user_conf_callback(const struct firmware *firmware,
				   void *context)
{
	bt_private *priv = (bt_private *)context;

	ENTER();

	if (!firmware)
		PRINTM(ERROR, "BT user init config request firmware failed\n");

	priv->init_user_cfg = firmware;
	priv->init_user_conf_wait_flag = TRUE;
	wake_up_interruptible(&priv->init_user_conf_wait_q);

	LEAVE();
	return;
}

/**
 *    @brief BT set user defined init data and param
 *
 *    @param priv     BT private handle
 *    @param cfg_file user cofig file
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_init_config(bt_private *priv, char *cfg_file)
{
	const struct firmware *cfg = NULL;
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if ((request_firmware(&cfg, cfg_file, priv->hotplug_device)) < 0) {
		PRINTM(FATAL, "BT: request_firmware() %s failed\n", cfg_file);
		ret = BT_STATUS_FAILURE;
		goto done;
	}
	if (cfg)
		ret = bt_process_init_cfg(priv, (u8 *)cfg->data, cfg->size);
	else
		ret = BT_STATUS_FAILURE;
done:
	if (cfg)
		release_firmware(cfg);
	LEAVE();
	return ret;
}

/**
 *    @brief BT process calibration data
 *
 *    @param priv    a pointer to bt_private structure
 *    @param data    a pointer to cal data
 *    @param size    cal data size
 *    @param mac     mac address buf
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_process_cal_cfg(bt_private *priv, u8 *data, u32 size, char *mac)
{
	u8 bt_mac[ETH_ALEN];
	u8 cal_data[32];
	u8 *mac_data = NULL;
	u32 cal_data_len;
	int ret = BT_STATUS_FAILURE;
	u8 *pcal_data = cal_data;

	memset(bt_mac, 0, sizeof(bt_mac));
	cal_data_len = sizeof(cal_data);
	if (BT_STATUS_SUCCESS !=
	    bt_parse_cal_cfg(data, size, cal_data, &cal_data_len)) {
		goto done;
	}
	if (mac != NULL) {
		/* Convert MAC format */
		bt_mac2u8(bt_mac, mac);
		PRINTM(CMD, "HCI: new BT Address " MACSTR "\n",
		       MAC2STR(bt_mac));
		mac_data = bt_mac;
	}
	if (BT_STATUS_SUCCESS != bt_load_cal_data(priv, pcal_data, mac_data)) {
		PRINTM(FATAL, "BT: Fail to load calibrate data\n");
		goto done;
	}
	ret = BT_STATUS_SUCCESS;

done:
	LEAVE();
	return ret;
}

/**
 *    @brief BT process calibration EXT data
 *
 *    @param priv    a pointer to bt_private structure
 *    @param data    a pointer to cal data
 *    @param size    cal data size
 *    @param mac     mac address buf
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_process_cal_cfg_ext(bt_private *priv, u8 *data, u32 size, int cfg_ext2)
{
	u8 cal_data[128];
	u32 cal_data_len;
	int ret = BT_STATUS_FAILURE;

	cal_data_len = sizeof(cal_data);
	if (BT_STATUS_SUCCESS !=
	    bt_parse_cal_cfg(data, size, cal_data, &cal_data_len)) {
		goto done;
	}
	if (BT_STATUS_SUCCESS !=
	    bt_load_cal_data_ext(priv, cal_data, cal_data_len, cfg_ext2)) {
		PRINTM(FATAL, "BT: Fail to load calibrate data\n");
		goto done;
	}
	ret = BT_STATUS_SUCCESS;

done:
	LEAVE();
	return ret;
}

/**
 *    @brief BT process calibration file
 *
 *    @param priv    a pointer to bt_private structure
 *    @param cal_file calibration file name
 *    @param mac     mac address buf
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_cal_config(bt_private *priv, char *cal_file, char *mac)
{
	const struct firmware *cfg = NULL;
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if (bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT,
					      cal_file, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      bt_request_init_user_conf_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cal_file, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      bt_request_init_user_conf_callback);
#endif
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 13)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cal_file, priv->hotplug_device,
					      priv,
					      bt_request_init_user_conf_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE,
					      cal_file, priv->hotplug_device,
					      priv,
					      bt_request_init_user_conf_callback);
#endif
#endif
		if (ret < 0) {
			PRINTM(FATAL,
			       "BT: bt_cal_config() failed, error code = %#x cal_file=%s\n",
			       ret, cal_file);
			ret = BT_STATUS_FAILURE;
			goto done;
		}
		priv->init_user_conf_wait_flag = FALSE;
		wait_event_interruptible(priv->init_user_conf_wait_q,
					 priv->init_user_conf_wait_flag);
		cfg = priv->init_user_cfg;
	} else {
		if ((request_firmware(&cfg, cal_file, priv->hotplug_device)) <
		    0) {
			PRINTM(FATAL, "BT: request_firmware() %s failed\n",
			       cal_file);
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	if (cfg)
		ret = bt_process_cal_cfg(priv, (u8 *)cfg->data, cfg->size, mac);
	else
		ret = BT_STATUS_FAILURE;
done:
	if (cfg)
		release_firmware(cfg);
	LEAVE();
	return ret;
}

/**
 *    @brief BT process calibration EXT file
 *
 *    @param priv    a pointer to bt_private structure
 *    @param cal_file calibration file name
 *    @param mac     mac address buf
 *    @return         BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_cal_config_ext(bt_private *priv, char *cal_file, int cfg_ext2)
{
	const struct firmware *cfg = NULL;
	int ret = BT_STATUS_SUCCESS;

	ENTER();
	if (bt_extflg_isset(priv, EXT_BT_REQ_FW_NOWAIT)) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_UEVENT,
					      cal_file, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      bt_request_init_user_conf_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cal_file, priv->hotplug_device,
					      GFP_KERNEL, priv,
					      bt_request_init_user_conf_callback);
#endif
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 13)
		ret = request_firmware_nowait(THIS_MODULE, FW_ACTION_HOTPLUG,
					      cal_file, priv->hotplug_device,
					      priv,
					      bt_request_init_user_conf_callback);
#else
		ret = request_firmware_nowait(THIS_MODULE,
					      cal_file, priv->hotplug_device,
					      priv,
					      bt_request_init_user_conf_callback);
#endif
#endif
		if (ret < 0) {
			PRINTM(FATAL,
			       "BT: bt_cal_config_ext() failed, error code = %#x cal_file=%s\n",
			       ret, cal_file);
			ret = BT_STATUS_FAILURE;
			goto done;
		}
		priv->init_user_conf_wait_flag = FALSE;
		wait_event_interruptible(priv->init_user_conf_wait_q,
					 priv->init_user_conf_wait_flag);
		cfg = priv->init_user_cfg;
	} else {
		if ((request_firmware(&cfg, cal_file, priv->hotplug_device)) <
		    0) {
			PRINTM(FATAL, "BT: request_firmware() %s failed\n",
			       cal_file);
			ret = BT_STATUS_FAILURE;
			goto done;
		}
	}
	if (cfg)
		ret = bt_process_cal_cfg_ext(priv, (u8 *)cfg->data, cfg->size,
					     cfg_ext2);
	else
		ret = BT_STATUS_FAILURE;
done:
	if (cfg)
		release_firmware(cfg);
	LEAVE();
	return ret;
}

/**
 *    @brief BT init mac address from bt_mac parametre when insmod
 *
 *    @param priv    a pointer to bt_private structure
 *    @param bt_mac  mac address buf
 *    @return        BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_init_mac_address(bt_private *priv, char *mac)
{
	u8 bt_mac[ETH_ALEN];
	int ret = BT_STATUS_FAILURE;

	ENTER();
	memset(bt_mac, 0, sizeof(bt_mac));
	bt_mac2u8(bt_mac, mac);
	PRINTM(CMD, "HCI: New BT Address " MACSTR "\n", MAC2STR(bt_mac));
	ret = bt_set_mac_address(priv, bt_mac);
	if (ret != BT_STATUS_SUCCESS)
		PRINTM(FATAL,
		       "BT: Fail to set mac address from insmod parametre.\n");

	LEAVE();
	return ret;
}

/**
 *  @brief This function duplicate a string
 *
 *  @param dst   A pointer to destination string
 *  @param src   A pointer to source string
 *
 *  @return      MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
void
sbi_dup_string(char **dst, char *src)
{
	size_t len = 0;
	if (src && (len = strlen(src)) != 0) {
		if (*dst != NULL)
			kfree(*dst);
		*dst = kzalloc(len + 1, GFP_KERNEL);
		if (*dst == NULL) {
			PRINTM(ERROR, "Failed to alloc mem for param: %s\n",
			       src);
			return;
		}
		memcpy(*dst, src, len);
	}
}

static void
bt_setup_module_param(bt_private *priv, bt_module_param * params)
{
	bt_adapter *adapter = priv->adapter;
	if (fw)
		bt_extflg_set(priv, EXT_FW);
	if (psmode)
		bt_extflg_set(priv, EXT_PSMODE);
	if (deep_sleep)
		bt_extflg_set(priv, EXT_DEEP_SLEEP);
	sbi_dup_string(&adapter->params.init_cmds, init_cmds);
	if (params)
		sbi_dup_string(&adapter->params.init_cmds, params->init_cmds);
	sbi_dup_string(&adapter->params.init_cfg, init_cfg);
	sbi_dup_string(&adapter->params.cal_cfg, cal_cfg);
	sbi_dup_string(&adapter->params.cal_cfg_ext, cal_cfg_ext);
	sbi_dup_string(&adapter->params.cal_cfg_ext2, cal_cfg_ext2);
	sbi_dup_string(&adapter->params.bt_mac, bt_mac);
	if (params) {
		sbi_dup_string(&adapter->params.init_cfg, params->init_cfg);
		sbi_dup_string(&adapter->params.cal_cfg, params->cal_cfg);
		sbi_dup_string(&adapter->params.cal_cfg_ext,
			       params->cal_cfg_ext);
		sbi_dup_string(&adapter->params.cal_cfg_ext2,
			       params->cal_cfg_ext2);
		sbi_dup_string(&adapter->params.bt_mac, params->bt_mac);
	}
	adapter->params.drv_mode = drv_mode;
	if (params)
		adapter->params.drv_mode = params->drv_mode;
	adapter->params.bt_fw_reload = bt_fw_reload;
	if (bt_fw_reload == FW_RELOAD_WITH_EMULATION) {
		/* FW_RELOAD_WITH_EMULATION for usb only */
		if (!IS_USB(adapter->card_type))
			adapter->params.bt_fw_reload = 0;
		else
			bt_fw_reload = 0;
	}
	if (params)
		adapter->params.bt_fw_reload = params->bt_fw_reload;
	adapter->params.mbt_gpio_pin = mbt_gpio_pin;
	if (params)
		adapter->params.mbt_gpio_pin = params->mbt_gpio_pin;
	adapter->params.btindrst = btindrst;
	if (params)
		adapter->params.btindrst = params->btindrst;
	if (btpmic)
		bt_extflg_set(priv, EXT_BTPMIC);
	if (bt_fw_serial)
		bt_extflg_set(priv, EXT_BT_FW_SERIAL);
	sbi_dup_string(&adapter->params.fw_name, fw_name);
	if (params)
		sbi_dup_string(&adapter->params.fw_name, params->fw_name);
	if (bt_req_fw_nowait)
		bt_extflg_set(priv, EXT_BT_REQ_FW_NOWAIT);
	if (params)
		memcpy(adapter->params.ext_flgs, params->ext_flgs,
		       sizeof(params->ext_flgs));
}

void
bt_free_module_param(bt_private *priv)
{
	bt_module_param *params = &priv->adapter->params;

	PRINTM(MSG, "Free module param\n");
	if (params->init_cmds) {
		kfree(params->init_cmds);
		params->init_cmds = NULL;
	}

	if (params->init_cfg) {
		kfree(params->init_cfg);
		params->init_cfg = NULL;
	}
	if (params->cal_cfg) {
		kfree(params->cal_cfg);
		params->cal_cfg = NULL;
	}
	if (params->cal_cfg_ext) {
		kfree(params->cal_cfg_ext);
		params->cal_cfg_ext = NULL;
	}
	if (params->cal_cfg_ext2) {
		kfree(params->cal_cfg_ext2);
		params->cal_cfg_ext2 = NULL;
	}
	if (params->bt_mac) {
		kfree(params->bt_mac);
		params->bt_mac = NULL;
	}
	if (params->fw_name) {
		kfree(params->fw_name);
		params->fw_name = NULL;
	}
}

/**
 *  @brief This function read card info in module parameter file
 *
 *  @param line     A pointer to a line
 *  @param type     A pointer to card type
 *  @param if_id    A pointer to interface id
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int
parse_line_read_card_info(u8 *line, char **type, char **if_id)
{
	u8 *p = NULL;
	int ret = BT_STATUS_SUCCESS;
	if (line == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	if ((p = strstr(line, "=")) == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	*p = '\0';
	if ((p = strstr(line, "_")) != NULL) {
		*p++ = '\0';
		*if_id = p;
	} else {
		*if_id = NULL;
	}
	*type = line;
out:
	return ret;
}

/**
 *  @brief This function read a string in module parameter file
 *
 *  @param line     A pointer to a line
 *  @param out_str  A pointer to parsed string
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int
parse_line_read_string(u8 *line, char **out_str)
{
	u8 *p = NULL, *pstr = NULL;
	int ret = BT_STATUS_SUCCESS;

	if (line == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	p = strstr(line, "=");
	if (p == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	p++;
	pstr = p;
	while (*pstr) {
		if (*pstr == '\"')
			*pstr = '\0';
		pstr++;
	}
	if (*p == '\0')
		p++;
	*out_str = p;
out:
	return ret;
}

/**
 *  @brief This function read an integer value in module parameter file
 *
 *  @param line     A pointer to a line
 *  @param out_data A pointer to parsed integer value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int
parse_line_read_int(u8 *line, int *out_data)
{
	u8 *p = NULL;
	int ret = BT_STATUS_SUCCESS;

	if (line == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	p = strstr(line, "=");
	if (p == NULL) {
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	p++;
	ret = bt_atoi(out_data, p);
out:
	if (ret != BT_STATUS_SUCCESS)
		*out_data = 0;
	return ret;
}

/**
 *  @brief This function read blocks in module parameter file
 *
 *  @param data     A pointer to a line
 *  @param size     line size
 *  @param handle   A pointer to moal_handle structure
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static int
parse_cfg_read_block(u8 *data, u32 size, bt_private *priv)
{
	int out_data = 0, end = 0;
	char *out_str = NULL;
	u8 line[MAX_LINE_LEN];
	bt_module_param *params = &priv->adapter->params;
	int ret = BT_STATUS_SUCCESS;

	while (parse_cfg_get_line(data, size, line) != -1) {
		if (strncmp(line, "}", strlen("}")) == 0) {
			end = 1;
			break;
		}
		if (end == 0 && strstr(line, "{") != 0)
			break;
		if (strncmp(line, "fw", strlen("fw")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_FW);
			else
				bt_extflg_clear(priv, EXT_FW);
			PRINTM(MSG, "fw %s\n",
			       bt_extflg_isset(priv, EXT_FW) ? "on" : "off");
		} else if (strncmp(line, "psmode", strlen("psmode")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_PSMODE);
			else
				bt_extflg_clear(priv, EXT_PSMODE);
			PRINTM(MSG, "psmode %s\n",
			       bt_extflg_isset(priv,
					       EXT_PSMODE) ? "on" : "off");
		} else if (strncmp(line, "deep_sleep", strlen("deep_sleep")) ==
			   0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_DEEP_SLEEP);
			else
				bt_extflg_clear(priv, EXT_DEEP_SLEEP);
			PRINTM(MSG, "deep_sleep %s\n",
			       bt_extflg_isset(priv,
					       EXT_DEEP_SLEEP) ? "on" : "off");
		} else if (strncmp(line, "init_cmds", strlen("init_cmds")) == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->init_cmds, out_str);
			PRINTM(MSG, "init_cmds=%s\n", params->init_cmds);
		} else if (strncmp(line, "init_cfg", strlen("init_cfg")) == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->init_cfg, out_str);
			PRINTM(MSG, "init_cfg=%s\n", params->init_cfg);
		} else if (strncmp(line, "cal_cfg", strlen("cal_cfg")) == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->cal_cfg, out_str);
			PRINTM(MSG, "cal_cfg=%s\n", params->cal_cfg);
		} else if (strncmp(line, "cal_cfg_ext", strlen("cal_cfg_ext"))
			   == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->cal_cfg_ext, out_str);
			PRINTM(MSG, "cal_cfg_ext=%s\n", params->cal_cfg_ext);
		} else if (strncmp(line, "cal_cfg_ext2", strlen("cal_cfg_ext2"))
			   == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->cal_cfg_ext2, out_str);
			PRINTM(MSG, "cal_cfg_ext2=%s\n", params->cal_cfg_ext2);
		} else if (strncmp(line, "bt_mac", strlen("bt_mac")) == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->bt_mac, out_str);
			PRINTM(MSG, "bt_mac=%s\n", params->bt_mac);
		} else if (strncmp(line, "drv_mode", strlen("drv_mode")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			params->drv_mode = out_data;
			PRINTM(MSG, "drv_mode = %d\n", params->drv_mode);
		} else if (strncmp(line, "bt_fw_reload", strlen("bt_fw_reload"))
			   == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			params->bt_fw_reload = out_data;
			PRINTM(MSG, "bt_fw_reload=%d\n", params->bt_fw_reload);
		} else if (strncmp(line, "mbt_gpio_pin", strlen("mbt_gpio_pin"))
			   == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			params->mbt_gpio_pin = out_data;
			PRINTM(MSG, "mbt_gpio_pin %d\n", params->mbt_gpio_pin);
		} else if (strncmp(line, "btindrst", strlen("btindrst")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			params->btindrst = out_data;
			PRINTM(MSG, "btindrst %d\n", params->btindrst);
		} else if (strncmp(line, "btpmic", strlen("btpmic")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_BTPMIC);
			else
				bt_extflg_clear(priv, EXT_BTPMIC);
			PRINTM(MSG, "btpmic %s\n",
			       bt_extflg_isset(priv,
					       EXT_BTPMIC) ? "on" : "off");
		} else if (strncmp(line, "bt_fw_serial", strlen("bt_fw_serial"))
			   == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_BT_FW_SERIAL);
			else
				bt_extflg_clear(priv, EXT_BT_FW_SERIAL);
			PRINTM(MSG, "bt_fw_serial %s\n",
			       bt_extflg_isset(priv,
					       EXT_BT_FW_SERIAL) ? "on" :
			       "off");
		} else if (strncmp(line, "fw_name", strlen("fw_name")) == 0) {
			if (parse_line_read_string(line, &out_str) !=
			    BT_STATUS_SUCCESS)
				goto err;
			sbi_dup_string(&params->fw_name, out_str);
			PRINTM(MSG, "fw_name=%s\n", params->fw_name);
		} else if (strncmp
			   (line, "bt_req_fw_nowait",
			    strlen("bt_req_fw_nowait")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_BT_REQ_FW_NOWAIT);
			else
				bt_extflg_clear(priv, EXT_BT_REQ_FW_NOWAIT);
			PRINTM(MSG, "bt_req_fw_nowait %s\n",
			       bt_extflg_isset(priv,
					       EXT_BT_REQ_FW_NOWAIT) ? "on" :
			       "off");
		} else if (strncmp(line, "block", strlen("block")) == 0) {
			if (parse_line_read_int(line, &out_data) !=
			    BT_STATUS_SUCCESS)
				goto err;
			if (out_data)
				bt_extflg_set(priv, EXT_BT_BLOCK_CMD);
			else
				bt_extflg_clear(priv, EXT_BT_BLOCK_CMD);
		}
	}
	if (end)
		return ret;
err:
	PRINTM(MSG, "Invalid line: %s\n", line);
	ret = BT_STATUS_FAILURE;
	return ret;
}

/**
 *  @brief This function checks the interrupt status
 *
 *  @param priv    A pointer to bt_private structure
 *  @param mod_file A pointer to module param file path
 *  @return        BT_STATUS_SUCCESS
 */
static int
sbi_req_mod_param(struct device *dev, bt_private *priv, char *mod_file)
{
	int ret = BT_STATUS_SUCCESS;
	if (dev == NULL) {
		PRINTM(ERROR, "No device attached\n");
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	if ((ret =
	     request_firmware(&priv->adapter->param_data, mod_file, dev) < 0))
		PRINTM(ERROR, "Request firmware: %s failed, error: %d\n",
		       mod_file, ret);
out:
	return ret;
}

/**
 *  @brief This function check if configuration block id could be used
 *
 *  @param priv   A pointer to bt_private structure
 *
 *  @return       BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
bt_validate_cfg_id(bt_private *priv)
{
	int i, ret = BT_STATUS_SUCCESS;
	for (i = 0; i < MAX_BT_ADAPTER; i++) {
		if (m_priv[i] == NULL || m_priv[i] == priv)
			continue;
		if (m_priv[i]->adapter->card_type == priv->adapter->card_type) {
			if (m_priv[i]->adapter->blk_id == priv->adapter->blk_id) {
				ret = BT_STATUS_FAILURE;
			}
		}
	}
	return ret;
}

/**
 *  @brief This function skip current configuration block
 *
 *  @param data   A pointer to buffer of module configuration file
 *  @param size   Size of module configuration file
 *
 *  @return       BT_STATUS_SUCCESS or BT_STATUS_FAILURE
 */
int
parse_skip_cfg_block(u8 *data, u32 size)
{
	int end = 0;
	u8 line[MAX_LINE_LEN];
	while (parse_cfg_get_line(data, size, line) != -1) {
		if (strncmp(line, "}", strlen("}")) == 0) {
			end = 1;
			break;
		}
		if (end == 0 && strstr(line, "{") != 0)
			break;
	}
	return (end == 1) ? BT_STATUS_SUCCESS : BT_STATUS_FAILURE;
}

/**
 *  @brief This function handle fallback processing for invalid
 *  block id with same card type
 *
 *  @param priv   A pointer to bt_private structure
 *
 *  @return       MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
int
bt_cfg_fallback_process(bt_private *priv)
{
	int i, blk_id = 0x7fffffff, idx = -1;
	int ret = BT_STATUS_FAILURE;
	PRINTM(MSG, "Configuration block, fallback processing\n");
	for (i = 0; i < MAX_BT_ADAPTER; i++) {
		if (m_priv[i] == NULL || m_priv[i] == priv ||
		    m_priv[i]->adapter->card_type != priv->adapter->card_type)
			continue;
		/* use configuratino with lowest blk_id value */
		if (m_priv[i]->adapter->blk_id >= 0 &&
		    m_priv[i]->adapter->blk_id <= blk_id) {
			idx = i;
			blk_id = m_priv[i]->adapter->blk_id;
		}
	}
	if (idx >= 0 && idx < MAX_BT_ADAPTER) {
		ret = BT_STATUS_SUCCESS;
		priv->adapter->blk_id = m_priv[idx]->adapter->blk_id;
		PRINTM(MSG,
		       "Configuration fallback to, card_type: 0x%x, blk_id: 0x%x\n",
		       priv->adapter->card_type, priv->adapter->blk_id);
		bt_setup_module_param(priv, &m_priv[idx]->adapter->params);
	}
	return ret;
}

/**
 *  @brief This function init module params
 *
 *  @param priv    A pointer to bt_private structure
 *  @return        BT_STATUS_SUCCESS
 */
int
bt_init_module_param(struct device *dev, bt_private *priv)
{
	u32 tbl_size, i, size;
	u8 line[MAX_LINE_LEN], *data = NULL;
	char *card_type = NULL, *blk_id = NULL;
	int ret = BT_STATUS_SUCCESS, no_match = 1;;

#ifdef CONFIG_OF
	bt_init_from_dev_tree();
#endif
	bt_setup_module_param(priv, NULL);
	if (bt_mod_para == NULL) {
		PRINTM(MSG, "No module param cfg file specified\n");
		goto out;
	}
	if (sbi_req_mod_param(dev, priv, bt_mod_para)) {
		PRINTM(ERROR, "Failed to get module param file\n");
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	tbl_size = sizeof(card_type_map_tbl) / sizeof(card_type_map_tbl[0]);
	for (i = 0; i < tbl_size; i++)
		if (priv->adapter->card_type == card_type_map_tbl[i].card_type)
			break;
	if (i >= tbl_size) {
		PRINTM(ERROR, "No card type entry found for card type: 0x%x\n",
		       priv->adapter->card_type);
		ret = BT_STATUS_FAILURE;
		goto out;
	}
	PRINTM(MSG, "%s: init module param from usr cfg\n",
	       card_type_map_tbl[i].name);
	size = priv->adapter->param_data->size;
	data = (u8 *)priv->adapter->param_data->data;
	while (parse_cfg_get_line(data, size, line) != -1) {
		if (line[0] == '#')
			continue;
		if (strstr(line, "={")) {
			if ((ret = parse_line_read_card_info(line,
							     &card_type,
							     &blk_id)) !=
			    BT_STATUS_SUCCESS)
				goto out;
			PRINTM(INFO,
			       "Traverse, card_type: %s, config block: %s\n",
			       card_type, blk_id);
			if (strcmp(card_type_map_tbl[i].name, card_type) == 0) {
				/* parse config block id */
				if (blk_id == NULL)
					priv->adapter->blk_id = 0;
				else
					bt_atoi(&priv->adapter->blk_id, blk_id);
				PRINTM(INFO,
				       "Validation check, %s, config block: %d\n",
				       card_type, priv->adapter->blk_id);
				/* check validation of config id */
				if (bt_validate_cfg_id(priv) !=
				    BT_STATUS_SUCCESS) {
					ret = parse_skip_cfg_block(data, size);
					if (ret != BT_STATUS_SUCCESS) {
						PRINTM(INFO,
						       "failed to skip block\n");
						goto out;
					}
					continue;
				}
				no_match = 0;
				PRINTM(MSG, "card_type: %s, config block: %d\n",
				       card_type, priv->adapter->blk_id);
				/* parse config block */
				if ((ret =
				     parse_cfg_read_block(data, size,
							  priv)) !=
				    BT_STATUS_SUCCESS)
					goto out;
				break;
			}
		}
	}
	if (no_match)
		ret = bt_cfg_fallback_process(priv);
out:
	if (priv->adapter->param_data) {
		release_firmware(priv->adapter->param_data);
		/* rewind pos */
		parse_cfg_get_line(NULL, 0, NULL);
	}
	if (ret != BT_STATUS_SUCCESS) {
		bt_free_module_param(priv);
		bt_setup_module_param(priv, NULL);
	}
	return ret;
}

#ifdef CONFIG_OF
/**
 *  @brief This function read the initial parameter from device tress
 *
 *
 *  @return         N/A
 */
void
bt_init_from_dev_tree(void)
{
	struct device_node *dt_node = NULL;
	struct property *prop;
	u32 data;
	const char *string_data;

	ENTER();

	if (!dts_enable) {
		PRINTM(CMD, "DTS is disabled!");
		return;
	}

	dt_node = of_find_node_by_name(NULL, "sdxxx-bt");
	if (!dt_node) {
		LEAVE();
		return;
	}
	for_each_property_of_node(dt_node, prop) {
#ifdef DEBUG_LEVEL1
		if (!strncmp(prop->name, "mbt_drvdbg", strlen("mbt_drvdbg"))) {
			if (!of_property_read_u32(dt_node, prop->name, &data)) {
				PRINTM(CMD, "mbt_drvdbg=0x%x\n", data);
				mbt_drvdbg = data;
			}
		}
#endif
		else if (!strncmp(prop->name, "init_cmds", strlen("init_cmds"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				init_cmds = (char *)string_data;
				PRINTM(CMD, "init_cmds=%s\n", init_cmds);
			}
		}

		else if (!strncmp(prop->name, "init_cfg", strlen("init_cfg"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				init_cfg = (char *)string_data;
				PRINTM(CMD, "init_cfg=%s\n", init_cfg);
			}
		} else if (!strncmp
			   (prop->name, "cal_cfg_ext", strlen("cal_cfg_ext"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				cal_cfg_ext = (char *)string_data;
				PRINTM(CMD, "cal_cfg_ext=%s\n", cal_cfg_ext);
			}
		} else if (!strncmp
			   (prop->name, "cal_cfg_ext2",
			    strlen("cal_cfg_ext2"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				cal_cfg_ext = (char *)string_data;
				PRINTM(CMD, "cal_cfg_ext2=%s\n", cal_cfg_ext2);
			}
		} else if (!strncmp(prop->name, "cal_cfg", strlen("cal_cfg"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				cal_cfg = (char *)string_data;
				PRINTM(CMD, "cal_cfg=%s\n", cal_cfg);
			}
		} else if (!strncmp(prop->name, "bt_mac", strlen("bt_mac"))) {
			if (!of_property_read_string
			    (dt_node, prop->name, &string_data)) {
				bt_mac = (char *)string_data;
				PRINTM(CMD, "bt_mac=%s\n", bt_mac);
			}
		} else if (!strncmp
			   (prop->name, "mbt_gpio_pin",
			    strlen("mbt_gpio_pin"))) {
			if (!of_property_read_u32(dt_node, prop->name, &data)) {
				mbt_gpio_pin = data;
				PRINTM(CMD, "mbt_gpio_pin=%d\n", mbt_gpio_pin);
			}
		} else if (!strncmp(prop->name, "btindrst", strlen("btindrst"))) {
			if (!of_property_read_u32(dt_node, prop->name, &data)) {
				btindrst = data;
				PRINTM(CMD, "btindrst=%d\n", btindrst);
			}
		} else if (!strncmp(prop->name, "btpmic", strlen("btpmic"))) {
			if (!of_property_read_u32(dt_node, prop->name, &data)) {
				btpmic = data;
				PRINTM(CMD, "btpmic=%d\n", btpmic);
			}
		}
	}
	LEAVE();
	return;
}
#endif

module_param(bt_mod_para, charp, 0);
MODULE_PARM_DESC(bt_mod_para, "Module parameter file name");

module_param(fw, int, 0);
MODULE_PARM_DESC(fw, "0: Skip firmware download; otherwise: Download firmware");
module_param(psmode, int, 0);
MODULE_PARM_DESC(psmode, "1: Enable powermode; 0: Disable powermode");
module_param(deep_sleep, int, 0);
MODULE_PARM_DESC(deep_sleep, "1: Enable deep sleep; 0: Disable deep sleep");
#ifdef CONFIG_OF
module_param(dts_enable, int, 0);
MODULE_PARM_DESC(dts_enable, "0: Disable DTS; 1: Enable DTS");
#endif
#ifdef	DEBUG_LEVEL1
module_param(mbt_drvdbg, uint, 0);
MODULE_PARM_DESC(mbt_drvdbg, "BIT3:DBG_DATA BIT4:DBG_CMD 0xFF:DBG_ALL");
#endif
module_param(init_cmds, charp, 0);
MODULE_PARM_DESC(init_cmds, "BT init commands file name");
module_param(init_cfg, charp, 0);
MODULE_PARM_DESC(init_cfg, "BT init config file name");
module_param(cal_cfg, charp, 0);
MODULE_PARM_DESC(cal_cfg, "BT calibrate file name");
module_param(cal_cfg_ext, charp, 0);
MODULE_PARM_DESC(cal_cfg_ext, "BT calibrate ext file name");
module_param(cal_cfg_ext2, charp, 0);
MODULE_PARM_DESC(cal_cfg_ext2,
		 "BT calibrate ext file name support Annex_100/101");
module_param(bt_mac, charp, 0660);
MODULE_PARM_DESC(bt_mac, "BT init mac address");
module_param(drv_mode, int, 0);
MODULE_PARM_DESC(drv_mode, "Bit 0: BT/AMP/BLE;");
module_param(bt_fw_reload, int, 0);
MODULE_PARM_DESC(bt_fw_reload,
		 "0: disable fw_reload; 1: enable fw reload feature");
module_param(mbt_gpio_pin, int, 0);
MODULE_PARM_DESC(mbt_gpio_pin,
		 "GPIO pin to interrupt host. 0xFF: disable GPIO interrupt mode; Others: GPIO pin assigned to generate pulse to host.");
module_param(btindrst, int, 0);
MODULE_PARM_DESC(btindrst,
		 "Independent reset configuration; high byte:GPIO pin number;low byte:0x0:disable, 0x1:out-band reset, 0x2:in-band reset.");
module_param(btpmic, int, 0);
MODULE_PARM_DESC(btpmic,
		 "1: Send pmic configure cmd to firmware; 0: No pmic configure cmd sent to firmware (default)");
module_param(bt_fw_serial, int, 0);
MODULE_PARM_DESC(bt_fw_serial,
		 "0: Support parallel download FW; 1: Support serial download FW");
module_param(fw_name, charp, 0);
MODULE_PARM_DESC(fw_name, "Firmware name");
module_param(bt_req_fw_nowait, int, 0);
MODULE_PARM_DESC(bt_req_fw_nowait,
		 "0: Use request_firmware API; 1: Use request_firmware_nowait API");
