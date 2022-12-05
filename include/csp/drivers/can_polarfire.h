#pragma once

/**
   @file

   Polarfire SOC  CAN driver (Linux).

   This driver requires the Polarfire SOC .
   The test are been perfomed on icicle kit.
**/

#include <csp/interfaces/csp_if_can.h>
#define SYSFS_PATH_LEN		   (128)
#define ID_STR_LEN		        (32)
#define UIO_DEVICE_PATH_LEN	    (32)
#define NUM_UIO_DEVICES         (32)


#define NUM_MSGS	        (1)

#define NUM_RX_MAILBOXES    (32)
#define NUM_TX_MAILBOXES    (32)

#define DLC 8    
#define CAN_SET_TSEG2(_tseg2)		(_tseg2 << 5)
#define CAN_SET_TSEG1(_tseg1)		(_tseg1 << 8)
#define CAN_SET_BITRATE(_bitrate)	(_bitrate << 16)

#define CAN_SPEED_8M_1M		(CAN_SET_BITRATE(0) | CAN_SET_TSEG1(4) | CAN_SET_TSEG2(1))

#define CAN_TX_REQ		    (1 << 0)
#define CAN_TX_ABORT		(1 << 1)
#define CAN_TX_INT_ENB		(1 << 2)
#define CAN_TX_WPNL_ENB		(1 << 3)
#define CAN_TX_WPNH_ENB		(1 << 23)
#define CAN_TX_DLC          (0x8 << 16)
#define CAN_TX_EXTENDED     (1<<20)



#define CAN_RX_MSGAV		    (1 << 0)
#define CAN_RX_RTRP		        (1 << 1)
#define CAN_RX_RTR_ABORT	    (1 << 2)
#define CAN_RX_BUFFER_ENB	    (1 << 3)
#define CAN_RX_RTR_REPLY_ENB    (1 << 4)
#define CAN_RX_INT_ENB	    	(1 << 5)
#define CAN_RX_LINK_ENB         (1 << 6)
#define CAN_RX_WPNL_ENB         (1 << 7)
#define CAN_RX_WPNH_ENB         (1 << 23)

#define CAN_INT_GLOBAL		    (1 << 0)
#define CAN_INT_ARB_LOSS	    (1 << 2)
#define CAN_INT_OVR_LOAD	    (1 << 3)
#define CAN_INT_BIT_ERR	        (1 << 4)
#define CAN_INT_STUFF_ERR	    (1 << 5)
#define CAN_INT_ACK_ERR	        (1 << 6)
#define CAN_INT_FORM_ERR	    (1 << 7)
#define CAN_INT_CRC_ERR		    (1 << 8)
#define CAN_INT_BUS_OFF		    (1 << 9)
#define CAN_INT_RX_MSG_LOST	    (1 << 10)
#define CAN_INT_TX_MSG		    (1 << 11)
#define CAN_INT_RX_MSG		    (1 << 12)
#define CAN_INT_RTR_MSG		    (1 << 13)
#define CAN_INT_STUCK_AT_0	    (1 << 14)
#define CAN_INT_SST_FAILURE	    (1 << 15)

#define CAN_MODE_NORMAL		    (0x01)
#define CAN_MODE_LISTEN_ONLY	(0x03)
#define CAN_MODE_EXT_LOOPBACK	(0x05)
#define CAN_MODE_INT_LOOPBACK	(0x07)
#define CAN_SRAM_TEST	    	(0x08)
#define CAN_SW_RESET	    	(0x10)

#define CMD_RUN_STOP_ENB    	(1 << 0)


struct can_msg {
	uint32_t msgid;
	uint32_t datal;
	uint32_t datah;
	uint32_t flags;
	uint8_t dlc;
};

struct mss_can_filter {
	uint32_t amr;
	uint32_t acr;
	uint16_t amcr_d_mask;
	uint16_t amcr_d_code;
};

struct can_txmsg {
	uint32_t txb;
	uint32_t msgid;
	uint32_t datal;
	uint32_t datah;
};

struct can_rxmsg {
	uint32_t rxb;
	uint32_t msgid;
    uint32_t datal;
	uint32_t datah;
	uint32_t amr;
	uint32_t acr;
	uint32_t amr_d;
	uint32_t acr_d;
};
struct can_device {
	uint32_t int_status;
	uint32_t int_enb;
	uint32_t rx_buf_status;
	uint32_t tx_buf_status;
	uint32_t err_status;
	uint32_t cmd;
	uint32_t cfg;
	uint32_t ecr;
	struct can_txmsg txmsg[NUM_TX_MAILBOXES];
	struct can_rxmsg rxmsg[NUM_RX_MAILBOXES];
};



/**
   Open CAN socket and add CSP interface.

   @param[in] device CAN device name (Linux device).
   @param[in] ifname CSP interface name, use #CSP_IF_CAN_DEFAULT_NAME for default name.
   @param[in] bitrate if different from 0, it will be attempted to change the bitrate on the CAN device - this may require increased OS privileges.
   @param[in] promisc if  true, receive all CAN frames. If \a false a filter is set on the CAN device, using device->addr
   @param[out] return_iface the added interface.
   @return The added interface, or NULL in case of failure.
*/
int polarfire_CAN_open_and_add_interface(const char * device, const char * ifname, int bitrate, bool promisc, csp_iface_t ** return_iface);


/**
 * @brief CAN controller Initilizatoin POLARFIRE SOC
 * @param[in] dev Contains the driver data of pfsoc .
 * @param[in] bitrate Maximum baud rate of 1 Mbps with 8 MHz CAN clock
 */
void can_init(volatile struct can_device * dev, uint32_t bitrate);


/**
 * @brief CAN Controller Operaions MODES(Listen Only mode: 1, Internal Loopback mode:2 , External Loopback mode:3 ,SRAM Test mode:4 )
 * @param[in] dev Contains the driver data of pfsoc.
 * @param[in] mode Modes set to pull pin high described in the brief
 */
void can_set_mode(volatile struct can_device *dev,uint32_t mode);


/**
 * @brief Starting the CAN controller and initializing the buffers and filters  
 * 
 */
void can_start(volatile struct can_device *dev);


/**
 * @brief Set the CAN recivecing Filter modes acceptance mask register (AMR) and acceptance code register (ACR) pair.
 * Filters Covers 
 * ID
 * IDE
 * RTR
 * Data byte 1 and data byte 2
 */

void can_cfg_buf(volatile struct can_device *dev, struct mss_can_filter *filter);


/**
 * @brief Enabling IRQ registers for PFSOC
 *  @param[in] int_enb Interrupts varibale, need to set the IRQ source before TX OR RX 
 */
void can_set_int_enb( volatile struct can_device *dev, uint32_t int_enb);


/**
 * @brief Maps the address on the HW (Polarfire SOC)
 * open the file the describes the memory range size.
 * this is set up by the reg property of the node in the device tree
 */

uint32_t get_memory_size(char *sysfs_path, char *devname);

/**
 * @brief Locate the UIO CAN device mapped by the UIO driver
 * 
 */

int get_uio_device(const char * id);

/**
 * @brief Sanity check if the message is avaible in the RX buffer 
 * If the LSB is 0x1 the interupt is been trigered and acknowlege by file desciptor else interrupt is not triggered
 * HINT: cat /proc/interrupts displays the total interrupt count
 */

int can_get_msg_av(volatile struct can_device *dev);


/**
 * @brief PFSOC received function
 * The data in recieve buffer is passed to msg struct and later to csp_can_rx 
 * 
 */

int can_get_msg(volatile struct can_device *dev, struct can_msg *msg);



/**
 * @brief Sanity check if the file desciptor is Valid
 * 
 */
int is_valid_fd(int fd);

/**
 * @brief Sanity check for checking ERROR frames on the HW level 
 * 
 */


void print_ints(uint32_t val);

/**
 * @brief BIT shifting Endiannes 
 * 
 */

void to_uint8_t(uint32_t value, uint8_t* result);



