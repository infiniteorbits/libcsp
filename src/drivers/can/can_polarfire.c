

#include <csp/drivers/can_socketcan.h>
#include <csp/drivers/can_polarfire.h>
#include <pthread.h>
#include <stdlib.h>
#include <csp/csp_debug.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/can/raw.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/can.h>
#include <csp/csp.h>



uint32_t verbose = 1;
char uio_id_str[] = "can@2010c000";
char sysfs_template[] = "/sys/class/uio/uio%d/%s";


// CAN interface data, state, etc.
static struct can_driver {
	char name[CSP_IFLIST_NAME_MAX + 1];
	csp_iface_t iface;
	csp_can_interface_data_t ifdata;
	pthread_t rx_thread;
	//int socket;
	int uiofd;
    volatile struct can_device  *dev;
}ctx ={

	.iface= {
			.name = "CAN",
			//.addr=0x000000002010c000,
			.interface_data = &ctx.ifdata,
			.driver_data = &ctx,
			
		},

};


/**Mapping the CAN device on PFSOC**/

uint32_t get_memory_size(char *sysfs_path, char *devname){
	FILE *fp;
	uint32_t sz;
    int unused __attribute__((unused));

	/* 
	 * open the file the describes the memory range size.
	 * this is set up by the reg property of the node in the device tree
	*/
	fp = fopen(sysfs_path, "r");
	if (fp == NULL) {
		fprintf(stderr, "unable to determine size for %s\n", devname);
		exit(0);
	}

    unused=fscanf(fp, "0x%016X", &sz);
	fclose(fp);

	return sz;
}

int get_uio_device(const char * id){
	FILE *fp;
	int i;
	int len;
	char file_id[ID_STR_LEN];
	char sysfs_path[SYSFS_PATH_LEN];
	int unused __attribute__((unused));

	for (i = 0; i < NUM_UIO_DEVICES; i++) {
		snprintf(sysfs_path, SYSFS_PATH_LEN, sysfs_template, i, "/name");
		fp = fopen(sysfs_path, "r");
		if (fp == NULL)
			break;

		unused=fscanf(fp, "%32s", file_id);

		len = strlen(id);
		if (len > ID_STR_LEN-1)
			len = ID_STR_LEN-1;

		if (strncmp(file_id, id, len) == 0)
			return i;
	}

	return -1;
}




/**CAN INIT, Buffer Init , CAN MODE**/
void can_init(volatile struct can_device * dev, uint32_t bitrate){
    int i;
   	for (i = 0; i < NUM_RX_MAILBOXES; i++) {
		dev->rxmsg[i].msgid = 0;
		dev->rxmsg[i].datal = 0;
		dev->rxmsg[i].datah = 0;
		dev->rxmsg[i].amr = 0;
		dev->rxmsg[i].acr = 0;
		dev->rxmsg[i].amr_d = 0;
		dev->rxmsg[i].acr_d = 0;
		dev->rxmsg[i].rxb = CAN_RX_WPNH_ENB | CAN_RX_WPNL_ENB | CAN_RX_BUFFER_ENB |CAN_RX_INT_ENB ;
	}

	dev->cfg = bitrate;
}


void can_set_mode(volatile struct can_device *dev,uint32_t mode){
	
	dev->cmd &= ~CMD_RUN_STOP_ENB;
	dev->cmd = mode;
}

void can_start(volatile struct can_device *dev){

	dev->int_enb = 0;
	dev->cmd |= CMD_RUN_STOP_ENB;
	dev->int_enb |= CAN_INT_GLOBAL | CAN_INT_RX_MSG| CAN_INT_TX_MSG ;
}

void can_cfg_buf(volatile struct can_device *dev, struct mss_can_filter *filter){
	int i;
  	csp_print("*dev=%x\n",*dev);
  	csp_print("&dev=%x\n",&dev);

	for (i = 0; i < NUM_RX_MAILBOXES; i++) {
		dev->rxmsg[i].acr = filter->acr;
		dev->rxmsg[i].amr = filter->amr;
		dev->rxmsg[i].amr_d = filter->amcr_d_mask;
		dev->rxmsg[i].acr_d = filter->amcr_d_code;

		dev->rxmsg[i].rxb = CAN_RX_WPNH_ENB | CAN_RX_WPNL_ENB |CAN_RX_BUFFER_ENB | CAN_RX_INT_ENB | CAN_RX_LINK_ENB;

		/* Unset link flag for last buffer */
		if (i == NUM_RX_MAILBOXES-1){
           dev->rxmsg[i].rxb &= ~CAN_RX_LINK_ENB;
		}
			
	}
}

void can_set_int_enb( volatile struct can_device *dev, uint32_t int_enb){
	
	dev->int_enb = int_enb;	
}

/**Sanity CHECKS**/
int is_valid_fd(int fd)
{
    return fcntl(fd, F_GETFL) != -1 || errno != EBADF;
}
void print_ints(uint32_t val)
{
	if (val & CAN_INT_GLOBAL)
		printf("CAN_INT_GLOBAL\n");
	if (val & CAN_INT_ARB_LOSS)
		printf("CAN_INT_ARB_LOSS\n");
	if (val & CAN_INT_OVR_LOAD)
		printf("CAN_INT_OVR_LOAD\n");
	if (val & CAN_INT_BIT_ERR)
		printf("CAN_INT_BIT_ERR\n");
	if (val & CAN_INT_STUFF_ERR)
		printf("CAN_INT_STUFF_ERR\n");
	if (val & CAN_INT_ACK_ERR)
		printf("CAN_INT_ACK_ERR\n");
	if (val & CAN_INT_FORM_ERR)
		printf("CAN_INT_FORM_ERR\n");
	if (val & CAN_INT_CRC_ERR)
		printf("CAN_INT_CRC_ERR\n");
	if (val & CAN_INT_BUS_OFF)
		printf("CAN_INT_BUS_OFF\n");
	if (val & CAN_INT_RX_MSG_LOST)
		printf("CAN_INT_RX_MSG_LOST\n");
	if (val & CAN_INT_TX_MSG)
		printf("CAN_INT_TX_MSG\n");
	if (val & CAN_INT_RX_MSG)
		printf("CAN_INT_RX_MSG\n");
	if (val & CAN_INT_RTR_MSG)
		printf("CAN_INT_RTR_MSG\n");
	if (val & CAN_INT_STUCK_AT_0)
		printf("CAN_INT_STUCK_AT_0\n");
	if (val & CAN_INT_SST_FAILURE)
		printf("CAN_INT_SST_FAILURE\n");
	if (val & 0xffff0002)
		printf("RESERVED\n");
}

uint32_t can_get_int_status(volatile struct can_device *dev){
	
	return dev->int_status;
}

void can_set_int_status(volatile struct can_device *dev, uint32_t status){    
    dev->int_status = status;

}

/**CAN RX**/

int can_get_msg_av(volatile struct can_device *dev)
{
	int i;

	for (i = 0; i < NUM_RX_MAILBOXES; i++) 
	{
		if (dev->rxmsg[i].rxb & CAN_RX_MSGAV){
            return 1;
		}
			
	}

	return 0;
}

int can_get_msg(volatile struct can_device *dev, struct can_msg *msg)
{
	int i;
	uint32_t temp;

	for (i = 0; i < NUM_RX_MAILBOXES; i++){
		if (dev->rxmsg[i].rxb & CAN_RX_MSGAV){
			msg->msgid = dev->rxmsg[i].msgid>>3;
			msg->datal = dev->rxmsg[i].datal;
			msg->datah = dev->rxmsg[i].datah;
         	msg->flags = dev->rxmsg[i].rxb;
			temp= dev->rxmsg[i].rxb;
			msg->dlc= (temp>>16)&0xf;
			/* ack the message */
			dev->rxmsg[i].rxb |= CAN_RX_MSGAV;
			return 1;
			
		}
	}

	return 0;
}


void to_uint8_t(uint32_t value, uint8_t* result){
    for(uint16_t i = 0; i< 4;i++){
        result[3 - i] = (value >> (i * 8))& 0xff; /* little endian*/
      	   //result[i] = (value >> (i * 8))& 0xff; /* big endian*/
	}
}

static void * rx_callback(void * arg)
{
    struct can_driver *rx_driver=arg;
	struct mss_can_filter filter;
	uint8_t result[8];
	struct can_msg msg;
	int ret;
	int unused __attribute__((unused));

	filter.acr = 0;
	filter.amr = 0xffffffff;
	filter.amcr_d_mask = 0xffff;
	filter.amcr_d_code = 0x0;
	can_cfg_buf(rx_driver->dev, &filter);
	
    while (1){
        uint32_t reenable = 1;
    
        struct pollfd fds = {
		    .fd = rx_driver->uiofd,
	 	    .events = POLLIN,
	    };
	
        int ret1 = poll(&fds, 1,100);
	
        if (ret1 == -1) {
	    	fprintf(stderr, "poll error\n");
		    exit(-1);
	    }

	    if (ret1 >= 1){    
		    if (fds.revents & POLLIN){
                unused= read(rx_driver->uiofd, &reenable, sizeof(int));
			    while ((ret = can_get_msg_av(rx_driver->dev))){
				    ret = can_get_msg(rx_driver->dev, &msg);
				    to_uint8_t(msg.datal, result);
                    to_uint8_t(msg.datah, result + 4);
				    /**Need to shift and Mask the REG*/
				    csp_can_rx(&rx_driver->iface, msg.msgid, result, msg.dlc, NULL);
			    }
		        unused= write(rx_driver->uiofd, &reenable, sizeof(int));
		    }
	    }
   }
   	
}

/**CAN TX**/

static int  csp_can_tx_frame(void * driver_data, uint32_t id, const uint8_t * data, uint8_t dlc) {
  
	uint32_t high = 0;
	uint32_t low  = 0;
    //struct can_msg msg;
	struct can_driver *driver_tx= driver_data;
	const uint8_t * tx_data=data; 
	unsigned int offset = 32;
 
	if (dlc > 8){
		return CSP_ERR_INVAL;
	}

	for(int i = 0; i < dlc; ++i){
		offset -= 4;
		high |= (uint32_t)(*tx_data >> 4)   << offset;
		low  |= (uint32_t)(*tx_data & 0x0f) << offset;
		++tx_data;
	}
	
	uint32_t var = ((high & 0xF0000000)>>0)|((low & 0xF0000000)>>4)|
	               ((high & 0x0F000000)>>4)|((low & 0x0F000000)>>8)|
		           ((high & 0x00F00000)>>8)|((low & 0x00F00000)>>12)|
                   ((high & 0x000F0000)>>12)|((low & 0x000F0000)>>16);    


	uint32_t var1 = ((low & 0x0000000F)<<0)|((high & 0x0000000F)<<4)|
	                ((low & 0x000000F0)<<4)|((high & 0x000000F0)<<8)|
		            ((low & 0x00000F00)<<8)|((high & 0x00000F00)<<12)|
                    ((low & 0x0000F000)<<12)|((high & 0x0000F000)<<16) ;   
/*
csp_print("var=%x\n",var);
csp_print("var1=%x\n",var1);

memcpy(&msg.datal, &var ,4);
memcpy(&msg.datah, &var1 ,4);

csp_print("msg.datal=%x\n",msg.datal);
csp_print("msg.datah=%x\n",msg.datah);
*/
 
    struct mss_can_filter filter;
    filter.acr = 0;
	filter.amr = 0xffffffff;
	filter.amcr_d_mask = 0xffff;
	filter.amcr_d_code = 0x0;
    can_cfg_buf(driver_tx->dev, &filter);
	
	for (int i = 0; i < NUM_TX_MAILBOXES; i++) {
		/* find first idle mailbox and use it */
		if ((driver_tx->dev->tx_buf_status & (1 << i)) == 0){
			driver_tx->dev->txmsg[i].msgid = id<<3;;
			driver_tx->dev->txmsg[i].datal = var;
			driver_tx->dev->txmsg[i].datah = var1;
			//dev->txmsg[i].dlc = msg->dlc;
			driver_tx->dev->txmsg[i].txb = (CAN_TX_INT_ENB | CAN_TX_WPNH_ENB | CAN_TX_WPNL_ENB | CAN_TX_EXTENDED | dlc<<16| CAN_TX_REQ);
            return CSP_ERR_NONE;
		}
	  return -1;
	}

	return CSP_ERR_NONE;
}

int polarfire_CAN_open_and_add_interface(const char * device, const char * ifname, int bitrate, bool promisc, csp_iface_t ** return_iface) {
	
	int index;
	char devname[UIO_DEVICE_PATH_LEN];
	uint32_t mmap_size;
	char sysfs_path[SYSFS_PATH_LEN];
	uint32_t int_enb = CAN_INT_ACK_ERR | CAN_INT_TX_MSG | CAN_INT_GLOBAL |
		               CAN_INT_RX_MSG | CAN_INT_BUS_OFF | CAN_INT_BIT_ERR |
					   CAN_INT_OVR_LOAD | CAN_INT_FORM_ERR | CAN_INT_CRC_ERR |
				       CAN_INT_RX_MSG_LOST | CAN_INT_RTR_MSG | CAN_INT_STUCK_AT_0 |
					   CAN_INT_STUFF_ERR | CAN_INT_SST_FAILURE | CAN_INT_ARB_LOSS;
	uint32_t bitrate_set = CAN_SPEED_8M_1M;

	if (ifname == NULL) {
		ifname = CSP_IF_CAN_DEFAULT_NAME;
	}

	csp_print("INIT %s: device: [%s], bitrate: %d, promisc: %d\n", ifname, device, bitrate, promisc);
    
    printf("locating device for %s\n", device);
    index = get_uio_device(device);

	if (index < 0) {
		fprintf(stderr, "can't locate uio device for %s\n", device);
		return -1;
	}

	snprintf(devname, UIO_DEVICE_PATH_LEN, "/dev/uio%d", index);
	printf("located %s\n", devname);

	ctx.uiofd = open(devname, O_RDWR);

	if(ctx.uiofd < 0) {
		fprintf(stderr, "cannot open %s: %s\n", devname, strerror(errno));
		return -1;
	} else {
		printf("opened %s (r,w)\n", devname);
	}

	snprintf(sysfs_path, SYSFS_PATH_LEN, sysfs_template, index, "maps/map0/size");
	mmap_size = get_memory_size(sysfs_path, devname);
	if (mmap_size == 0) {
		fprintf(stderr, "bad memory size for %s\n", devname);
		return -1;
	}

	ctx.dev = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED,ctx.uiofd, 0);
	if (ctx.dev == MAP_FAILED) {
		fprintf(stderr, "cannot mmap %s: %s\n", devname, strerror(errno));
		return -1;
	} else {
		printf("mapped 0x%x bytes for %s\n", mmap_size, devname);
	}
    
	
	is_valid_fd(ctx.uiofd);
	can_init(ctx.dev, bitrate_set);
	can_set_mode(ctx.dev,CAN_MODE_NORMAL);
	can_start(ctx.dev);	
    can_set_int_enb(ctx.dev, int_enb);
    
  	strncpy(ctx.name, ifname, sizeof(ctx.name) - 1);
	ctx.iface.name = ctx.name;
    ctx.iface.interface_data = &ctx.ifdata;
    ctx.iface.driver_data = &ctx;
    ctx.ifdata.tx_func = csp_can_tx_frame;
	ctx.ifdata.pbufs = NULL;

	int res = csp_can_add_interface(&ctx.iface);
	if (res != CSP_ERR_NONE) {
		csp_print("%s[%s]: csp_can_add_interface() failed, error: %d\n", __FUNCTION__, ctx.name, res);
		//socketcan_free(ctx);
		return res;
	}

   /* Create receive thread */
	if (pthread_create(&ctx.rx_thread, NULL, rx_callback, &ctx) != 0) {
		csp_print("%s[%s]: pthread_create() failed, error: %s\n", __FUNCTION__, ctx.name, strerror(errno));
		// socketcan_free(ctx); // we already added it to CSP (no way to remove it)
		return CSP_ERR_NOMEM;
	}
		
	if (return_iface) {
		*return_iface = &ctx.iface;
	}

	return CSP_ERR_NONE;
}


