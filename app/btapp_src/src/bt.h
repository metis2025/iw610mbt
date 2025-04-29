/** @file  bt.h
  *
  * @brief This file contains definitions for BT application
  *
  *
  * Copyright 2022-2023 NXP
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

#ifndef __BT_H
#define __BT_H

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
**
** INCLUDE FILES
**
*******************************************************************************/

#include <sys/socket.h>

/**********************************************************************************
**
** MACROS
**
***********************************************************************************/
#define VERSION_NUMBER "1.3"

/* Byte order conversions */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobs(d) (d)
#define htobl(d) (d)
#define btohs(d) (d)
#define btohl(d) (d)
#else
#if __BYTE_ORDER == __BIG_ENDIAN
#define htobs(d) bswap_16(d)
#define htobl(d) bswap_32(d)
#define btohs(d) bswap_16(d)
#define btohl(d) bswap_32(d)
#else
#error "Unknown byte order"
#endif
#endif

#define HCI_MAX_DEV 16

#define HCI_MAX_ACL_SIZE 2048
#define HCI_MAX_SCO_SIZE 255
#define HCI_MAX_EVENT_SIZE 260
#define HCI_MAX_FRAME_SIZE (HCI_MAX_ACL_SIZE + 4)

#define EVT_CMD_STATUS 0x0F
#define EVT_CMD_STATUS_SUCCESS 0x00

#define HCI_COMMAND_PKT 0x01
#define HCI_EVENT_HDR_SIZE 2
#define HCI_COMMAND_HDR_SIZE 3
#define EVT_CMD_COMPLETE 0x0E
#define EVT_PHY_LINK_COMPLETE 0x40
#define EVT_CHANNEL_SELECTED 0x41
#define EVT_LOG_LINK_COMPLETE 0x45
#define EVT_MODE_CHANGE 0x14
#define EVT_CONNECTION_COMPLETE 0x03

/* Command opcode pack/unpack */
#define cmd_opcode_pack(ogf, ocf) (uint16_t)((ocf & 0x03ff) | (ogf << 10))
#define cmd_opcode_ogf(op) (op >> 10)
#define cmd_opcode_ocf(op) (op & 0x03ff)

#define OPEN_FAILURE -1
#define TIMEOUT_SEC 5
/**************************************************************************************
**
** STRUCTURES
**
***************************************************************************************/

	typedef struct {
		uint8_t status;
		uint8_t ncmd;
		uint16_t opcode;
	} __attribute__((packed)) evt_cmd_status;

	typedef struct {
		uint8_t evt;
		uint8_t plen;
	} __attribute__((packed)) hci_event_hdr;

	typedef struct {
		uint8_t ncmd;
		uint16_t opcode;
	} __attribute__((packed)) evt_cmd_complete;

#ifdef __cplusplus
}
#endif
#endif				/* __BT_H */
