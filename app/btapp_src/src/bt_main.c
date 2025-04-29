/** @file  bt_main.c
  *
  * @brief BT application
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

/************************************************************************
**
** INCLUDE FILES
**
*************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "bt.h"

/**********************************************************************************
**
**     MACROS
**
***********************************************************************************/
#define BT_PATH_MAX 256

#define PRINT_CMD(ogf, ocf, buf, len)                                          \
	do {                                                                   \
		printf("< HCI Command: ogf 0x%02x, ocf 0x%04x, plen %d\n",     \
		       (ogf), (ocf), (len));                                   \
		btapp_hex_dump("  ", 20, (buf), (len));                        \
		fflush(stdout);                                                \
	} while (0);

#define PRINT_EVT(hdr, ptr, len)                                               \
	do {                                                                   \
		printf("> HCI Event: 0x%02x plen %d\n", (hdr)->evt,            \
		       (hdr)->plen);                                           \
		btapp_hex_dump("  ", 20, (ptr), (len));                        \
		fflush(stdout);                                                \
	} while (0);

#define OpCodePack(ogf, ocf) (uint16_t)((ocf & 0x03ff) | (ogf << 10))
#define HCI_EVENT_PKT 0x04
/***************************************************************************************
**
** GLOBAL VARIABLES
**
***************************************************************************************/
static uint8_t verbose;

static struct option main_options[] = { {"help", 0, 0, 'h'},
{"verbose", 0, 0, 'v'},
{0, 0, 0, 0}
};

struct epoll_event event_test;
static int ep_fd = -1;
static int ep_ret;

/**************************************************************************************
**
** Coded Procedures
**
***************************************************************************************/

/**
 *  @brief                dump HCI cmd/evt
 *  @param pref      data pref for dump
 *  @param width    data line width for dump
 *  @param buf       data buf for dump
 *  @param len        data len for dump
 *  @return      	      N/A
 */
void
btapp_hex_dump(char *pref, int width, uint8_t * buf, int len)
{
	register int i, n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1) {
			printf("%s", pref);
		}
		printf("%2.2X ", buf[i]);
		if (n == width) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n != 1) {
		printf("\n");
	}
}

/**
 *  @brief this function creates event to be monitored by epoll
 *
 *  @return void
 */
void
init_epoll_event(int uart_fd)
{
	int ret = 0;
	ep_fd = epoll_create(1);
	event_test.events = EPOLLIN;
	event_test.data.fd = uart_fd;
	ret = epoll_ctl(ep_fd, EPOLL_CTL_ADD, uart_fd, &event_test);
	if (ret != 0) {
		printf("set epoll error!\n");
	}
}

/**
 *  @brief this function reads events from char port. These are the events
 *         for the command sent to controller.
 *
 *  @return number of bytes on success, otherwise error code
 */
int
read_hci_event(int fd, unsigned char *buf, int size)
{
	int para_size, r;
	int read_cnt = 0, num_bytes = 0;
	if (size <= 0) {
		printf("Invalid size argument!");
		return -1;
	}

	/* Check bytes to identifies HCI event packet, starting with 0x04. */
	do {
		r = read(fd, buf, 1);
		if (r <= 0)
			return -1;
		if (buf[0] == HCI_EVENT_PKT)
			break;
	} while (1);
	read_cnt++;
	/* Read next two bytes for event code and parameter total length. */
	do {
		r = read(fd, buf + read_cnt, 3 - read_cnt);
		if (r <= 0)
			return -1;
		read_cnt += r;
	} while (read_cnt < 3);

	/* Read remaining bytes based parameter total length */
	if (buf[2] < (size - 3))
		para_size = buf[2];
	else
		para_size = size - 3;

	/* check if complete parameter is ready to be read */
	do {
		r = ioctl(fd, FIONREAD, &num_bytes);
		if (num_bytes == para_size) {
			break;
		}
	} while (r < 0);

	while ((read_cnt - 3) < para_size) {
		r = read(fd, buf + read_cnt, para_size - (read_cnt - 3));
		if (r <= 0)
			return -1;
		read_cnt += r;
	}
	return read_cnt;
}

/**
 *  @brief              Return the baud rate corresponding to the frequency
 *  @param u32Rate      Frequency to be mapped to Baud rate
 *  @return             Baud rate mapped to Frequency
 */
static speed_t
uart_speed(unsigned int u32Rate)
{
	speed_t ulBaudrate = 0;
	switch (u32Rate) {
	case 9600:
		ulBaudrate = B9600;
		break;
	case 19200:
		ulBaudrate = B19200;
		break;
	case 38400:
		ulBaudrate = B38400;
		break;
	case 57600:
		ulBaudrate = B57600;
		break;
	case 115200:
		ulBaudrate = B115200;
		break;
	case 230400:
		ulBaudrate = B230400;
		break;
	case 460800:
		ulBaudrate = B460800;
		break;
	case 500000:
		ulBaudrate = B500000;
		break;
	case 576000:
		ulBaudrate = B576000;
		break;
	case 921600:
		ulBaudrate = B921600;
		break;
	case 1000000:
		ulBaudrate = B1000000;
		break;
	case 1152000:
		ulBaudrate = B1152000;
		break;
	case 1500000:
		ulBaudrate = B1500000;
		break;
	case 3000000:
		ulBaudrate = B3000000;
		break;
	case 4000000:
		ulBaudrate = B4000000;
		break;
	default:
		ulBaudrate = B0;
		break;
	}
	return ulBaudrate;
}

/**
 *  @brief        set input output UART speed
 *  @param fd     file descriptor for UART port
 *  @param ti     termios structure for fd
 *  @param speed  speed to set for UART port
 *  @return       0 on success, -1 otherwise
 */
static int
set_uart_speed(int fd, struct termios *ti, int speed)
{
	cfsetospeed(ti, (speed_t) uart_speed(speed));
	cfsetispeed(ti, (speed_t) uart_speed(speed));
	return tcsetattr(fd, TCSANOW, ti);
}

/**
 *  @brief            open bt char device
 *  @param dev        bt char device name
 *  @param baudrate   Baudrate at which UART port shall be opened
 *  @return           bt char device descriptor
 */
static int
init_chardev(char *dev, unsigned int baudrate)
{
	struct termios ti;
	int fd = open(dev, O_RDWR | O_NOCTTY);

	if (fd < 0) {
		perror("Can't open serial port");
		return OPEN_FAILURE;
	}

	if (tcgetattr(fd, &ti) < 0) {
		perror("Can't get port settings");
		close(fd);
		return OPEN_FAILURE;
	}
	tcflush(fd, TCIOFLUSH);
	cfmakeraw(&ti);
	ti.c_cflag |= (tcflag_t) (CLOCAL | CREAD);

	// Set 1 stop bit & no parity (8-bit data already handled by cfmakeraw)
	ti.c_cflag &= ~((tcflag_t) (CSTOPB | PARENB));

#ifdef CRTSCTS
	ti.c_cflag |= (tcflag_t) CRTSCTS;
#else
	ti.c_cflag |= (tcflag_t) IHFLOW;
	ti.c_cflag |= (tcflag_t) OHFLOW;
#endif

	// FOR READS: set timeout time w/ no minimum characters needed (since
	// we read only 1 at at time...)
	ti.c_cc[VMIN] = (cc_t) 0;
	ti.c_cc[VTIME] = (cc_t) TIMEOUT_SEC *10;

	tcflush(fd, TCIOFLUSH);

	if (tcsetattr(fd, TCSANOW, &ti) < 0) {
		perror("Can't set port settings");
		close(fd);
		return OPEN_FAILURE;
	}
	tcflush(fd, TCIOFLUSH);

	/* Set actual baudrate */
	if (set_uart_speed(fd, &ti, baudrate) < 0) {
		perror("Can't set baud rate");
		close(fd);
		return OPEN_FAILURE;
	}

	return fd;
}

/**
 *  @brief                  check evt/cmd status
 *  @param buf_ptr   pointer to HCi evt header
 *  @return      	        0:success,  other: fail
 */
int
check_evt_command_status(unsigned char *buf_ptr)
{
	evt_cmd_status *ecs;
	ecs = (evt_cmd_status *)buf_ptr;
	if (btohs(ecs->status) != EVT_CMD_STATUS_SUCCESS) {
		printf("Command Failed. Command Status Event received with Non-zero " "status.\n");
		return -1;
	}
	return 0;
}

/**
 *  @brief                wait cmd resp or event
 *  @param fd         file describe of bt char device
 *  @param ogf        Hci cmd ogf
 *  @param ocf        HCI cmd ocf
 *  @return      	       N/A
 */
void
bt_wait_for_cmd_complete(int fd, uint8_t ogf, uint16_t ocf)
{
	unsigned char *ptr;
	hci_event_hdr *hdr;
	evt_cmd_complete evt_cc, *ecc = &evt_cc;
	uint16_t opcode = 0;
	int len = 0;
	uint8_t buf[HCI_MAX_ACL_SIZE];

	memset(ecc, 0, sizeof(evt_cmd_complete));

	while (1) {
		// check read port ready
		do {
			ep_ret = epoll_wait(ep_fd, &event_test, 1, 100);
		} while (ep_ret <= 0);

		len = read_hci_event(fd, buf, HCI_MAX_EVENT_SIZE);
		if (len < 0) {
			printf("read_hci_event returned error. len=%d", len);
			return;
		}

		hdr = (void *)(buf + 1);
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		PRINT_EVT(hdr, ptr, len);

		if (hdr->evt == EVT_CMD_COMPLETE) {
			ecc = (evt_cmd_complete *)ptr;
			opcode = cmd_opcode_pack(ogf, ocf);
			if (btohs(ecc->opcode) == opcode) {
				return;
			}
		} else if (hdr->evt == EVT_CMD_STATUS) {
			if (check_evt_command_status(ptr)) {
				return;
			}
		} else if (hdr->evt == EVT_CONNECTION_COMPLETE) {
			return;
		} else {
			printf("Received Event Code %X\n", hdr->evt);
		}
	}
}

/**
 *  @brief                send cmd to bt char device
 *  @param fd         file describe of bt char device
 *  @param argc     number of arguments
 *  @param argv     A pointer to arguments array  (cmd content)
 *  @return      	      0:success,  other: fail
 */
int
bt_send_cmd(int fd, int argc, char **argv)
{
	uint16_t opcode;
	uint8_t cmd[512];
	int len = 0, i = 0, j = 4;
	uint16_t ogf, ocf;

	if (argc < 1) {
		printf("Did not provide cmd content\n");
		printf("Usage: drvtest <device>  [content]\n");
		exit(0);
	}

	ogf = strtol(argv[0], NULL, 16);
	ocf = strtol(argv[1], NULL, 16);

	opcode = OpCodePack(ogf, ocf);
	printf("ogf:%X, ocf:%X opcode:%x,  argc = %d\n", ogf, ocf, opcode,
	       argc);

	cmd[0] = HCI_COMMAND_PKT;
	cmd[1] = (uint8_t) opcode;
	cmd[2] = (uint8_t) (opcode >> 8);

	for (i = 2; i < argc; i++, len++) {
		cmd[j++] = (uint8_t) strtol(argv[i], NULL, 16);
	}

	cmd[3] = len;

	PRINT_CMD(ogf, ocf, cmd, len + 4)
		if (write(fd, cmd, len + 4) != (len + 4)) {
		perror("Can't write raw command");
		return -1;
	}

	bt_wait_for_cmd_complete(fd, ogf, ocf);
	return 0;
}

/**
 *  @brief Display usage
 *  @return      	N/A
 */
static void
usage(char *argv[])
{
	printf("btapp - Ver %s\n", VERSION_NUMBER);

	printf("Usage:\n"
	       "\tbtapp [options] devicename ogf ocf [command content]\n"
	       "\tdevicename example mbtchar0\n"
	       "\togf example 0x3f\n"
	       "\tocf example 0x280\n"
	       "\tCommands supported are as follows:\n");
	printf("Command Options:\n"
	       "\t-h\tDisplay help\n"
	       "\t-v\tVerbose\n" "\t-b\tbaudrate ( 3000000 default)\n");
	printf("Eg:\n\t %s -b 115200 ttymxc0 03 03 \n", argv[0]);
}

/**
 *  @brief Entry function for btapp
 *  @param argc		number of arguments
 *  @param argv     A pointer to arguments array
 *  @return      	0/1
 */
int
main(int argc, char *argv[])
{
	int opt = 0, baudrate = 3000000;
	char dev[BT_PATH_MAX];
	int fd = 0;
	char *optstr;

	optind = 0;

	while ((opt = getopt_long(argc, argv, "hvb:", main_options, NULL)) !=
	       -1) {
		switch (opt) {
		case 'v':
			verbose = 1;
			break;
		case 'b':
			baudrate = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv);
			return 0;
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 2) {
		usage(argv);
		return 0;
	}

	optstr = argv[0];

	dev[0] = 0;
	strcat(dev, "/dev/");
	strcat(dev, optstr);

	fd = init_chardev(dev, baudrate);
	if (fd == OPEN_FAILURE) {
		printf("Error while opening port (%s)", strerror(errno));
	} else {
		init_epoll_event(fd);
	}

	argv++;
	argc--;

	bt_send_cmd(fd, argc, argv);
	if (close(fd) < 0) {
		perror("Can't close serial port");
	}

	return 1;
}
