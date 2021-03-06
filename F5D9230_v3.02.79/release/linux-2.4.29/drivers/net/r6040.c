/* r6040.c: A RDC R6040 FastEthernet driver for linux. */
/*
	Re-written 2004 by Sten Wang.

	Copyright 1994-2000 by Donald Becker.
	Copyright 1993 United States Government as represented by the
	Director, National Security Agency.	 This software may be used and
	distributed according to the terms of the GNU General Public License,
	incorporated herein by reference.

	This driver is for RDC R6040 FastEthernet MAC series.
	For kernel version after 2.4.22

	Modification List
	----------	------------------------------------------------
	09-14-2006	Change the previous NAPI( Tx/Rx polling) to NAPI( Rx polling )
	08-24-2006	Support at linux 2.6.10 above
	03-24-2006	Support NAPI
	03-21-2006	By Charies,change spin_lock_irqsave(lp->lock, flags) to
			spin_lock_irqsave(&lp->lock, flags) in set_multicast_list
	03-15-2006      Modify the set_multicast_list ,due to when re-plug the ethernet,
			it will forget the previous setting
	07-12-2005      Tim, modify the set_multicast_list
	03-28-2005      Tim, modify some error mac register offset in 
	                function set_multicast_list
	03-27-2005	Tim, Add the internal state machine reset
			Sten, If multicast address more than 4, enter PROM mode
			Changed rdc to r6040
	12-22-2004	Sten Init MAC MBCR register=0x012A
			PHY_CAP = 0x01E1

	Need to Do List:
	1. If multicast address more than 4, use the multicast address hash
*/

#define DRV_NAME	"r6040"
#define DRV_VERSION	"0.14"
#define DRV_RELDATE	"14Sep2006"

#define FORICPLUS	/* Supports ICPlus IP175C switch chip */
#define BOOSTRDC        /* Accelerate Ethernet performance */



/* PHY CHIP Address */
#define PHY1_ADDR	1	/* For MAC1 */
#define PHY2_ADDR	2	/* For MAC2 */
#define PHY_MODE	0x3100	/* PHY CHIP Register 0 */
#define PHY_CAP		0x01E1	/* PHY CHIP Register 4 */

/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT  	(600 * HZ / 1000)
#define TIMER_WUT	(jiffies + HZ * 1)/* timer wakeup time : 1 second */

/* RDC MAC ID */
#define RDC_MAC_ID	0x6040

/* RDC MAC I/O Size */
#define R6040_IO_SIZE	256

/* RDC Chip PCI Command */
#define R6040_PCI_CMD	0x0005	/* IO, Master */

/* MAX RDC MAC */
#define MAX_MAC		2

/* MAC setting */
//#define TX_DCNT		40	/* TX descriptor count */
//#define RX_DCNT		256	/* RX descriptor count */
//#define TX_DCNT		40	/* TX descriptor count */
//#define RX_DCNT		128	/* RX descriptor count */
#define TX_DCNT		32	/* TX descriptor count */
#define RX_DCNT		128	/* RX descriptor count */

#define MAX_BUF_SIZE	0x600
#define ALLOC_DESC_SIZE	((TX_DCNT+RX_DCNT)*sizeof(struct r6040_descriptor)+0x10)
#define MBCR_DEFAULT	0x012A	/* MAC Bus Control Register */

/* Debug enable or not */
#define RDC_DEBUG	0

#if RDC_DEBUG > 1
#define RDC_DBUG(msg, value) printk("%s %x\n", msg, value);
#else
#define RDC_DBUG(msg, value)
#endif

#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#include <linux/moduleparam.h>
#endif
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/delay.h>	/* for udelay() */
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/crc32.h>
#include <linux/spinlock.h>

#include <asm/processor.h>
#include <asm/bitops.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/autoconf.h>
//Added by Keilven, 08/16/2006
#ifdef FAST_NAT
//  extern int shnat_hook_skb_to_ethlayer_snat(struct sk_buff *skb);
  extern software_nat_init(struct net_device *dev);
  extern void shnat_external_cmd(char *cmd);
#endif
#define CONFIG_R6040_NAPI

MODULE_AUTHOR("Sten Wang <sten.wang@rdc.com.tw>");
MODULE_LICENSE("GPL");
#ifdef CONFIG_R6040_NAPI
MODULE_DESCRIPTION("RDC R6040 NAPI PCI FastEthernet Driver");
#else
MODULE_DESCRIPTION("RDC R6040 PCI FastEthernet Driver");
#endif

#define RX_INT				0x0001
#define TX_INT				0x0010
#define RX_NO_DESC_INT			0x0002

#define R6040_INT_MASK			(RX_INT | TX_INT)

struct r6040_descriptor {
	u16	status, len;		/* 0-3 */
	u32	buf;			/* 4-7 */
	u32	ndesc;			/* 8-B */
	u32	rev1;			/* C-F */
	char	*vbufp;			/* 10-13 */
	struct r6040_descriptor *vndescp;	/* 14-17 */
	struct sk_buff *skb_ptr;	/* 18-1B */
	u32	rev2;			/* 1C-1F */
} __attribute__(( aligned(32) ));

struct r6040_private {
	struct net_device_stats stats;
	spinlock_t lock;
  	struct timer_list timer;
	struct pci_dev *pdev;

	struct r6040_descriptor *rx_insert_ptr;
	struct r6040_descriptor *rx_remove_ptr;
	struct r6040_descriptor *tx_insert_ptr;
	struct r6040_descriptor *tx_remove_ptr;
	u16	tx_free_desc, rx_free_desc, phy_addr, phy_mode;
	u16	mcr0, mcr1;
	int NAPI_RX_RUNNING ;
	dma_addr_t desc_dma;
	char	*desc_pool;
};

struct r6040_chip_info {
	const char *name;
	u16 pci_flags;
	int io_size;
	int drv_flags;
};

static int __devinitdata printed_version;
#ifdef CONFIG_R6040_NAPI
static char version[] __devinitdata =
	KERN_INFO DRV_NAME ": RDC R6040 ssNAPI net driver, version "DRV_VERSION " (" DRV_RELDATE ")\n";	
#else
static char version[] __devinitdata =
	KERN_INFO DRV_NAME ": RDC R6040 net driver, version "DRV_VERSION " (" DRV_RELDATE ")\n";	
#endif
static struct r6040_chip_info r6040_chip_info[] __devinitdata =
{
	{ "RDC R6040 Knight", R6040_PCI_CMD, R6040_IO_SIZE, 0}
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
static int NUM_MAC_TABLE = 2 ;
#endif

static int phy_table[] = { 0x5, 0x4};
static u8 adr_table[2][8] = {{0x00, 0x00, 0x60, 0x00, 0x00, 0x01}, {0x00, 0x00, 0x60, 0x00, 0x00, 0x02}};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	module_param_array(adr_table, int, &NUM_MAC_TABLE, 0644);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0) 
	module_param_array(adr_table, int, NUM_MAC_TABLE, 0644);
#else
	MODULE_PARM(adr_table, "2-4i");
#endif 
MODULE_PARM_DESC(adr_table, "MAC Address (assigned)");

static int r6040_open(struct net_device *dev);
static int r6040_start_xmit(struct sk_buff *skb, struct net_device *dev);
static irqreturn_t r6040_interrupt(int irq, void *dev_id, struct pt_regs *regs);
static struct net_device_stats *r6040_get_stats(struct net_device *dev);
static int r6040_close(struct net_device *dev);
static void set_multicast_list(struct net_device *dev);
static struct ethtool_ops netdev_ethtool_ops;
static int netdev_ioctl (struct net_device *dev, struct ifreq *rq, int cmd);
static void r6040_down(struct net_device *dev);
static void r6040_up(struct net_device *dev);
static void r6040_tx_timeout (struct net_device *dev);
static void r6040_timer(unsigned long);

static int phy_mode_chk(struct net_device *dev);
static int phy_read(int ioaddr, int phy_adr, int reg_idx);
static void phy_write(int ioaddr, int phy_adr, int reg_idx, int dat);
static void rx_buf_alloc(struct r6040_private *lp,struct net_device *dev);
static void rx_buf_alloc_onece(struct r6040_private *lp,struct net_device *dev);
#ifdef CONFIG_R6040_NAPI
static int r6040_poll(struct net_device *netdev, int *budget);
#endif

#ifdef FORICPLUS
static void process_ioctl(struct net_device*, unsigned long* );
#endif


static int __devinit r6040_init_one (struct pci_dev *pdev,
					 const struct pci_device_id *ent)
{
	struct net_device *dev;
	struct r6040_private *lp;
	int ioaddr, io_size, err;
	static int card_idx = -1; 
	int chip_id = (int)ent->driver_data;

	RDC_DBUG("r6040_init_one()", 0);

	if (printed_version++)
		printk(version);

	if ((err = pci_enable_device (pdev)))
		return err;

	/* this should always be supported */
	if (pci_set_dma_mask(pdev, 0xffffffff)) {
		printk(KERN_ERR DRV_NAME "32-bit PCI DMA addresses not supported by the card!?\n");
		return  -ENODEV;
	}

	/* IO Size check */
	io_size = r6040_chip_info[chip_id].io_size;
	if (pci_resource_len  (pdev, 0) < io_size) {
		return  -ENODEV;
	}

	ioaddr = pci_resource_start (pdev, 0);	/* IO map base address */
	pci_set_master(pdev);

	dev = alloc_etherdev(sizeof(struct r6040_private));
	if (dev == NULL)
		return -ENOMEM;
	SET_MODULE_OWNER(dev);

	if (pci_request_regions(pdev, DRV_NAME)) {
		printk(KERN_ERR DRV_NAME ": Failed to request PCI regions\n");
		err = -ENODEV;
		goto err_out_disable;
	}

	/* Init system & device */
	lp = dev->priv;
	dev->base_addr = ioaddr;
	dev->irq = pdev->irq;

	spin_lock_init(&lp->lock);
	pci_set_drvdata(pdev, dev);

	/* Set MAC address */
	card_idx++;
	memcpy(dev->dev_addr, (u8 *)&adr_table[card_idx][0], 6);

	/* Link new device into r6040_root_dev */
	lp->pdev = pdev;

	/* Init RDC private data */
	lp->mcr0 = 0x1002;
	lp->phy_addr = phy_table[card_idx];

	/* The RDC-specific entries in the device structure. */
	dev->open = &r6040_open;
	dev->hard_start_xmit = &r6040_start_xmit;
	dev->stop = &r6040_close;
	dev->get_stats = &r6040_get_stats;
	dev->set_multicast_list = &set_multicast_list;
	dev->do_ioctl = &netdev_ioctl;
	dev->ethtool_ops = &netdev_ethtool_ops;
	dev->tx_timeout = &r6040_tx_timeout;
	dev->watchdog_timeo = TX_TIMEOUT;
#ifdef CONFIG_R6040_NAPI
	dev->poll = &r6040_poll;
	dev->weight = 64;
#endif

	/* Register net device. After this dev->name assign */
	if ((err = register_netdev(dev))) {
		printk(KERN_ERR DRV_NAME ": Failed to register net device\n");
		goto err_out_res;
	}

	netif_carrier_on(dev);
	return 0;

err_out_res:
	pci_release_regions(pdev);
err_out_disable:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);

	return err;
}

static void __devexit r6040_remove_one (struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	
	unregister_netdev(dev);
	pci_release_regions(pdev);
	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int
r6040_open(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	int i;

	RDC_DBUG("r6040_open()", 0);

	/* Request IRQ and Register interrupt handler */
	i = request_irq(dev->irq, &r6040_interrupt, SA_SHIRQ, dev->name, dev);
	if (i) return i;

	/* Allocate Descriptor memory */
	lp->desc_pool = pci_alloc_consistent(lp->pdev, ALLOC_DESC_SIZE, &lp->desc_dma); 
	if (!lp->desc_pool) return -ENOMEM; 

	r6040_up(dev);

	netif_start_queue(dev);

	/* set and active a timer process */
	init_timer(&lp->timer);
	lp->timer.expires = TIMER_WUT;
	lp->timer.data = (unsigned long)dev;
	lp->timer.function = &r6040_timer;
	add_timer(&lp->timer);

#ifdef FAST_NAT  
  software_nat_init(dev);  //Added by Keilven, 08/16/2006
#endif

	return 0;
}

static void
r6040_tx_timeout (struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	//int ioaddr = dev->base_addr;
	//struct r6040_descriptor *descptr = lp->tx_remove_ptr;

	RDC_DBUG("r6040_tx_timeout()", 0);

	/* Transmitter timeout, serious problems. */
	/* Sten: Nothing need to do so far. */
	printk(KERN_ERR DRV_NAME ": Big Trobule, transmit timeout/n"); 
	lp->stats.tx_errors++;
	netif_stop_queue(dev);

//printk("<RDC> XMT timedout: CR0 %x, CR40 %x, CR3C %x, CR2C %x, CR30 %x, CR34 %x, CR38 %x\n", inw(ioaddr), inw(ioaddr+0x40), inw(ioaddr+0x3c), inw(ioaddr+0x2c), inw(ioaddr+0x30), inw(ioaddr+0x34), inw(ioaddr+0x38));

//printk("<RDC> XMT_TO: %08lx:%04x %04x %08lx %08lx %08lx %08lx\n", descptr, descptr->status, descptr->len, descptr->buf, descptr->skb_ptr, descptr->ndesc, descptr->vndescp);
}


static int
r6040_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	struct r6040_descriptor *descptr;
	int ioaddr = dev->base_addr;
	unsigned long flags;

	RDC_DBUG("r6040_start_xmit()", 0);

	if (skb == NULL)	/* NULL skb directly return */ 
		return 0;
	if (skb->len >= MAX_BUF_SIZE) {	/* Packet too long, drop it */
		dev_kfree_skb(skb);
		return 0;
	}

	/* Critical Section */
	spin_lock_irqsave(&lp->lock, flags);

	/* TX resource check */
	if (!lp->tx_free_desc) { 
		spin_unlock_irqrestore(&lp->lock, flags);
		printk(KERN_ERR DRV_NAME ": NO TX DESC "); 
		return 1;
	}

	/* Statistic Counter */
	lp->stats.tx_packets++;
	lp->stats.tx_bytes += skb->len;
	
	
	/* Set TX descriptor & Transmit it */
	lp->tx_free_desc--;
	descptr = lp->tx_insert_ptr;
	if (skb->len < 0x3c) descptr->len = 0x3c;
	else descptr->len = skb->len;
	descptr->skb_ptr = skb;
	descptr->buf = cpu_to_le32(pci_map_single(lp->pdev, skb->data, skb->len, PCI_DMA_TODEVICE));
	descptr->status = 0x8000;
	outw(0x01, ioaddr + 0x14);
	lp->tx_insert_ptr = descptr->vndescp;

#if RDC_DEBUG
 printk("Xmit(): %08lx:%04x %04x %08lx %08lx %08lx %08lx\n", descptr, descptr->status, descptr->len, descptr->buf, descptr->skb_ptr, descptr->ndesc, descptr->vndescp);
#endif 

	/* If no tx resource, stop */
	if (!lp->tx_free_desc) 
		netif_stop_queue(dev);

	dev->trans_start = jiffies;
	spin_unlock_irqrestore(&lp->lock, flags);
	return 0;
}

/* The RDC interrupt handler. */
static irqreturn_t
r6040_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = dev_id;
	struct r6040_private *lp;
	struct r6040_descriptor *descptr;
	struct sk_buff *skb_ptr;
	int ioaddr, status;
	unsigned long flags;
#ifdef CONFIG_R6040_NAPI	
	int handled = 1;
#else
	int handled = 0;
#endif	

	RDC_DBUG("r6040_interrupt()", 0);
	if (dev == NULL) {
		printk (KERN_ERR DRV_NAME ": INT() unknown device.\n");
		return IRQ_RETVAL(handled);
	}

	lp = (struct r6040_private *)dev->priv;
	spin_lock_irqsave(&lp->lock, flags);

	/* Check MAC Interrupt status */
	ioaddr = dev->base_addr;
	outw(0x0, ioaddr + 0x40);	/* Mask Off RDC MAC interrupt */
	status = inw(ioaddr + 0x3c);	/* Read INTR status and clear */
	
#ifdef CONFIG_R6040_NAPI		
	/* TX interrupt request */
	if (status & 0x10) {

		handled = 1;
		descptr = lp->tx_remove_ptr;
		while(lp->tx_free_desc < TX_DCNT) {
			if (descptr->status & 0x8000) break; /* Not complte */
			skb_ptr = descptr->skb_ptr;
			pci_unmap_single(lp->pdev, descptr->buf, skb_ptr->len, PCI_DMA_TODEVICE);
			dev_kfree_skb_irq(skb_ptr); /* Free buffer */
			descptr->skb_ptr = 0;
			descptr = descptr->vndescp; /* To next descriptor */
			lp->tx_free_desc++;
		}
		lp->tx_remove_ptr = descptr;
		if (lp->tx_free_desc) netif_wake_queue(dev);
	} 
	/* RX interrupt request */
	if ((status & 0x01) && !(lp->NAPI_RX_RUNNING))
	    {
	    if(netif_rx_schedule_prep(dev))	
	        {
		__netif_rx_schedule(dev);
	        }
	    }
	 
	if(lp->NAPI_RX_RUNNING)
	    outw( TX_INT , ioaddr + 0x40);	
	else	
	    outw( R6040_INT_MASK, ioaddr + 0x40);
	
	spin_unlock_irqrestore(&lp->lock, flags);
	return IRQ_RETVAL(handled);	

#else		
	/* TX interrupt request */
	if (status & 0x10) {
		handled = 1;
		descptr = lp->tx_remove_ptr;
		while(lp->tx_free_desc < TX_DCNT) {
			if (descptr->status & 0x8000) break; /* Not complte */
			skb_ptr = descptr->skb_ptr;
			pci_unmap_single(lp->pdev, descptr->buf, skb_ptr->len, PCI_DMA_TODEVICE);
			dev_kfree_skb_irq(skb_ptr); /* Free buffer */
			descptr->skb_ptr = 0;
			descptr = descptr->vndescp; /* To next descriptor */
			lp->tx_free_desc++;
		}
		lp->tx_remove_ptr = descptr;
		if (lp->tx_free_desc) netif_wake_queue(dev);
	} 

	/* RX interrupt request */
	if (status & 0x01) {
		handled = 1;
		descptr = lp->rx_remove_ptr;
		while(lp->rx_free_desc) {
			if (descptr->status & 0x8000) break; /* No Rx packet */
			skb_ptr = descptr->skb_ptr;
			descptr->skb_ptr = 0;
			skb_ptr->dev = dev;
			skb_put(skb_ptr, descptr->len - 4);
			pci_unmap_single(lp->pdev, descptr->buf, MAX_BUF_SIZE, PCI_DMA_FROMDEVICE);
      skb_ptr->protocol = eth_type_trans(skb_ptr, dev);
      netif_rx(skb_ptr);  /* Send to upper layer */
			lp->stats.rx_packets++;
			lp->stats.rx_bytes += descptr->len;
			descptr = descptr->vndescp; /* To next descriptor */
			lp->rx_free_desc--;
		}
		lp->rx_remove_ptr = descptr;
	}

	/* Allocate new RX buffer */
	if (lp->rx_free_desc < RX_DCNT) rx_buf_alloc(lp,dev);

	outw(R6040_INT_MASK, ioaddr + 0x40);	/* TX/RX interrupt enable */
	spin_unlock_irqrestore(&lp->lock, flags);
	
	return IRQ_RETVAL(handled);
#endif
	
}


static struct net_device_stats *
r6040_get_stats(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;

	RDC_DBUG("r6040_get_stats()", 0);
	return &lp->stats;
}

/*
 *     Set or clear the multicast filter for this adaptor.
 */
static void
set_multicast_list(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	struct dev_mc_list *mcptr;
	int ioaddr = dev->base_addr;
	u16 *adrp, i;
	unsigned long flags;

	RDC_DBUG("set_multicast_list()", 0);

	/* MAC Address */	
	adrp = (u16 *) dev->dev_addr;
	outw(adrp[0], ioaddr + 0x68); 
	outw(adrp[1], ioaddr + 0x6A); 
	outw(adrp[2], ioaddr + 0x6C); 


#if RDC_DEBUG 
	printk("MAC ADDR: %04x %04x %04x\n", adrp[0], adrp[1], adrp[2]);
#endif

	/* Promiscous Mode */
	spin_lock_irqsave(&lp->lock, flags);
	i = inw(ioaddr) & ~0x0120;		/* Clear AMCP & PROM */
	if (dev->flags & IFF_PROMISC)
	    {	
	 	i |= 0x0020;
		lp->mcr0 |= 0x0020 ;
	    }
	if (dev->mc_count > 4) i |= 0x0020;	/* Too many multicast address */
	outw(i, ioaddr);
	spin_unlock_irqrestore(&lp->lock, flags);
	
	/* Multicast Address */
	if (dev->mc_count > 4)	/* Wait to do: Hash Table for multicast */
		return;

	/* Multicast Address 1~4 case */
	for (i = 0, mcptr = dev->mc_list; (i<dev->mc_count) && (i<4); i++) {
		adrp = (u16 *)mcptr->dmi_addr;
		outw(adrp[0], ioaddr + 0x70 + 8*i); 
		outw(adrp[1], ioaddr + 0x72 + 8*i); 
		outw(adrp[2], ioaddr + 0x74 + 8*i); 
		mcptr = mcptr->next;
#if RDC_DEBUG 
	printk("M_ADDR: %04x %04x %04x\n", adrp[0], adrp[1], adrp[2]);
#endif
	}
	for (i = dev->mc_count; i < 4; i++) {
		outw(0xffff, ioaddr + 0x68 + 8*i); 
		outw(0xffff, ioaddr + 0x6A + 8*i); 
		outw(0xffff, ioaddr + 0x6C + 8*i); 
	}
}

static void netdev_get_drvinfo (struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct r6040_private *rp = dev->priv;

	strcpy (info->driver, DRV_NAME);
	strcpy (info->version, DRV_VERSION);
	strcpy (info->bus_info, pci_name(rp->pdev));
}

static struct ethtool_ops netdev_ethtool_ops = {
	.get_drvinfo		= netdev_get_drvinfo,
};

static int
r6040_close(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;

	RDC_DBUG("r6040_close()", 0);

 	/* deleted timer */
 	del_timer_sync(&lp->timer);

	spin_lock_irq(&lp->lock);

	netif_stop_queue(dev);

	r6040_down(dev);

	spin_unlock_irq(&lp->lock);

	return 0;
}

/**
 */
static int netdev_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
	RDC_DBUG("netdev_ioctl()", 0);

#ifdef FORICPLUS
	switch(cmd)
	{
		case SIOCDEVPRIVATE:
		
			//printk(KERN_INFO"Ethernet IOCTL: cmd SIOCDEVPRIVATE\n");	
			{
				unsigned long *data;
				unsigned long args[4];
	
				data = (unsigned long *)rq->ifr_data;
    				if (copy_from_user(args, data, 4*sizeof(unsigned long)))
                		return -EFAULT;
                		
                process_ioctl(dev, args);
            }
            break;
        
        default:
        	break;
	}
#endif	

	return 0;
}

/**
	Stop RDC MAC and Free the allocated resource
 */
static void r6040_down(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	int i;
	int ioaddr = dev->base_addr;

	RDC_DBUG("r6040_down()", 0);

	/* Stop MAC */
	outw(0x0000, ioaddr + 0x40);	/* Mask Off Interrupt */
	outw(0x0001, ioaddr + 0x04);	/* Reset RDC MAC */
	i = 0;
	do{}while((i++ < 2048) && (inw(ioaddr + 0x04) & 0x1));
	
	free_irq(dev->irq, dev);

	/* Free RX buffer */
	for (i = 0; i < RX_DCNT; i++) {
		if (lp->rx_insert_ptr->skb_ptr) {
			pci_unmap_single(lp->pdev, lp->rx_insert_ptr->buf, MAX_BUF_SIZE, PCI_DMA_FROMDEVICE);
			dev_kfree_skb(lp->rx_insert_ptr->skb_ptr);
			lp->rx_insert_ptr->skb_ptr = 0;
		}
		lp->rx_insert_ptr = lp->rx_insert_ptr->vndescp;
	}

	/* Free TX buffer */
	for (i = 0; i < TX_DCNT; i++) {
		if (lp->tx_insert_ptr->skb_ptr) {
			pci_unmap_single(lp->pdev, lp->tx_insert_ptr->buf, MAX_BUF_SIZE, PCI_DMA_TODEVICE);
			dev_kfree_skb(lp->tx_insert_ptr->skb_ptr);
			lp->rx_insert_ptr->skb_ptr = 0;
		}
		lp->tx_insert_ptr = lp->tx_insert_ptr->vndescp;
	}

	/* Free Descriptor memory */
	pci_free_consistent(lp->pdev, ALLOC_DESC_SIZE, lp->desc_pool, lp->desc_dma);
}



#ifdef CONFIG_R6040_NAPI
static int r6040_poll(struct net_device *dev, int *budget)
{
	struct r6040_private *lp;
	struct r6040_descriptor *descptr;
	struct sk_buff *skb_ptr;
	int ioaddr, status;
	unsigned long flags;
	
	ioaddr = dev->base_addr;	
	lp = (struct r6040_private *)dev->priv;
	unsigned long rx_work = dev->quota ;
	unsigned long rx ;
	
	/* Disable RX interrupt */
	local_irq_disable();
	lp->NAPI_RX_RUNNING = 1 ;
	outw(inw(ioaddr + 0x40) &  (~RX_INT)  ,ioaddr + 0x40 );
	local_irq_enable();	
	{						
		descptr = lp->rx_remove_ptr;
	  while(lp->rx_free_desc) 
	  {
	    if (descptr->status & 0x8000) 
	    {
	        break; /* No Rx packet */
	    }    
			skb_ptr = descptr->skb_ptr;
			descptr->skb_ptr = 0;
			skb_ptr->dev = dev;
			skb_put(skb_ptr, descptr->len - 4);
			pci_unmap_single(lp->pdev, descptr->buf, MAX_BUF_SIZE, PCI_DMA_FROMDEVICE);
      skb_ptr->protocol = eth_type_trans(skb_ptr, dev);             		  
      netif_receive_skb(skb_ptr); /* Send to upper layer */
			lp->stats.rx_packets++;
			lp->stats.rx_bytes += descptr->len;
			descptr = descptr->vndescp; /* To next descriptor */
			lp->rx_free_desc--;
			//printk("r6040_poll:lp->rx_free_desc:%d \n",lp->rx_free_desc);
		}
		lp->rx_remove_ptr = descptr;		
	}
	/* Allocate new RX buffer */
	if (lp->rx_free_desc < RX_DCNT) rx_buf_alloc_onece(lp,dev);
	
	local_irq_disable();
	netif_rx_complete(dev);
	lp->NAPI_RX_RUNNING = 0 ;
	/* Enable RX interrupt */
	outw(inw(ioaddr + 0x40)| RX_INT  ,ioaddr + 0x40 );
	//netif_rx_complete(dev);	
	local_irq_enable();
		
	return 0;	
}
#endif

/* Init RDC MAC */
static void r6040_up(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	struct r6040_descriptor *descptr;
	int i;
	int ioaddr = dev->base_addr;
	u32 tmp_addr;
	dma_addr_t desc_dma, start_dma;
	
	RDC_DBUG("r6040_up()", 0);

	/* Initilize */
	lp->tx_free_desc = TX_DCNT;
	lp->rx_free_desc = 0;

	lp->NAPI_RX_RUNNING =0;

	/* Init descriptor */
	memset(lp->desc_pool, 0, ALLOC_DESC_SIZE); /* Let all descriptor = 0 */
	lp->tx_insert_ptr = (struct r6040_descriptor *)lp->desc_pool;
	lp->tx_remove_ptr = lp->tx_insert_ptr;
	lp->rx_insert_ptr = (struct r6040_descriptor *)lp->tx_insert_ptr+TX_DCNT;
	lp->rx_remove_ptr = lp->rx_insert_ptr;
	
	/* Init TX descriptor */
	descptr = lp->tx_insert_ptr;
	desc_dma = lp->desc_dma;
	start_dma = desc_dma;
	for (i = 0; i < TX_DCNT; i++) {
		descptr->ndesc = cpu_to_le32(desc_dma + sizeof(struct r6040_descriptor));
		descptr->vndescp = (descptr + 1);
		descptr = (descptr + 1);
		desc_dma += sizeof(struct r6040_descriptor);
	}
	(descptr - 1)->ndesc = cpu_to_le32(start_dma);
	(descptr - 1)->vndescp = lp->tx_insert_ptr;

	/* Init RX descriptor */
	start_dma = desc_dma;
	descptr = lp->rx_insert_ptr;
	for (i = 0; i < RX_DCNT; i++) {
		descptr->ndesc = cpu_to_le32(desc_dma + sizeof(struct r6040_descriptor));
		descptr->vndescp = (descptr + 1);
		descptr = (descptr + 1);
		desc_dma += sizeof(struct r6040_descriptor);
	}
	(descptr - 1)->ndesc = cpu_to_le32(start_dma);
	(descptr - 1)->vndescp = lp->rx_insert_ptr;

	/* Allocate buffer for RX descriptor */
	rx_buf_alloc(lp,dev);

#if RDC_DEBUG 
descptr = lp->tx_insert_ptr;
for (i = 0; i < TX_DCNT; i++) {
 printk("%08lx:%04x %04x %08lx %08lx %08lx %08lx\n", descptr, descptr->status, descptr->len, descptr->buf, descptr->skb_ptr, descptr->ndesc, descptr->vndescp);
 descptr = descptr->vndescp;
}
descptr = lp->rx_insert_ptr;
for (i = 0; i < RX_DCNT; i++) {
 printk("%08lx:%04x %04x %08lx %08lx %08lx %08lx\n", descptr, descptr->status, descptr->len, descptr->buf, descptr->skb_ptr, descptr->ndesc, descptr->vndescp);
 descptr = descptr->vndescp;
}
#endif

	/* MAC operation register */
	outw(0x01, ioaddr+0x04);	/* Reset MAC */
        outw(2   , ioaddr+0xAC);        /* Reset internal state machine */
	outw(0   , ioaddr+0xAC);
	udelay(5000);

	/* TX and RX descriptor start Register */
	tmp_addr = cpu_to_le32(lp->tx_insert_ptr);
	tmp_addr = virt_to_bus((volatile void *)tmp_addr);
	outw((u16) tmp_addr, ioaddr+0x2c);
	outw(tmp_addr >> 16, ioaddr+0x30);
	tmp_addr = cpu_to_le32(lp->rx_insert_ptr);
	tmp_addr = virt_to_bus((volatile void *)tmp_addr);
	outw((u16) tmp_addr, ioaddr+0x34);
	outw(tmp_addr >> 16, ioaddr+0x38);

	/* Buffer Size Register */
	outw(MAX_BUF_SIZE, ioaddr+0x18);

#if 0//def FORICPLUS

	if(phy_read(ioaddr, 0, 2) == 0x0243)	// ICPlus IP175C Signature
	{
		phy_write(ioaddr, 29,31, 0x175C);	//Enable registers
	}
	lp->phy_mode = 0x8000;

#else
	if(phy_read(ioaddr, 0, 2) == 0x0243)	// ICPlus IP175C Signature
	{
		phy_write(ioaddr, 29,31, 0x175C);	//Enable registers
	}
	/* PHY Mode Check */
	phy_write(ioaddr, lp->phy_addr, 4, PHY_CAP);
	phy_write(ioaddr, lp->phy_addr, 0, PHY_MODE);

	if (PHY_MODE == 0x3100) 
		lp->phy_mode = phy_mode_chk(dev);
	else 
    lp->phy_mode = (PHY_MODE & 0x0100) ? 0x8000:0x0;
#endif 

#ifdef CONFIG_R6040_NAPI
	/* Sending 15 Tx packets ,only generate one interrupt */
        outw(0xFFFF, ioaddr+ 0x0C);
#endif
	
	/* MAC Bus Control Register */
	outw(MBCR_DEFAULT, ioaddr+0x8);

	/* MAC TX/RX Enable */
	lp->mcr0 |= lp->phy_mode;
	outw(lp->mcr0, ioaddr);

#ifdef FORICPLUS
	/* upgrade performance (by RDC guys) */
	//phy_write(ioaddr,30,17,(phy_read(ioaddr,30,17)|0x4000));	//bit 14=1
	//phy_write(ioaddr,30,17,~((~phy_read(ioaddr,30,17))|0x2000));	//bit 13=0
	//phy_write(ioaddr,0,19,0x0000);
	//phy_write(ioaddr,0,30,0x01F0);
#endif

	/* Interrupt Mask Register */
	outw(R6040_INT_MASK, ioaddr + 0x40);
}

/*
  A periodic timer routine
	Polling PHY Chip Link Status
*/
static void r6040_timer(unsigned long data)
{
 	struct net_device *dev=(struct net_device *)data;
	struct r6040_private *lp = dev->priv;
	u16 ioaddr = dev->base_addr, phy_mode;
 
 	RDC_DBUG("r6040_timer()", 0);

	/* Polling PHY Chip Status */
	if (PHY_MODE == 0x3100) 
		phy_mode = phy_mode_chk(dev);
	else phy_mode = (PHY_MODE & 0x0100) ? 0x8000:0x0;

	if (phy_mode != lp->phy_mode) {
		lp->phy_mode = phy_mode;
		lp->mcr0 = (lp->mcr0 & 0x7fff) | phy_mode;
		outw(lp->mcr0, ioaddr);
		printk("<RDC> Link Change %x \n", inw(ioaddr));
	}

	/* Debug */
//	printk("<RDC> Timer: CR0 %x CR40 %x CR3C %x\n", inw(ioaddr), inw(ioaddr+0x40), inw(ioaddr+0x3c));

 	/* Timer active again */
 	lp->timer.expires = TIMER_WUT;
 	add_timer(&lp->timer);
}

/* Allocate skb buffer for rx descriptor */
static void rx_buf_alloc_onece(struct r6040_private *lp,struct net_device *dev)
{
	struct r6040_descriptor *descptr;
	int ioaddr = dev->base_addr ;
	int i = 0;

	//RDC_DBUG
	//printk("rx_buf_alloc()");
	descptr = lp->rx_insert_ptr;
	while( (lp->rx_free_desc < RX_DCNT) && (i < (RX_DCNT/16)) ){
		descptr->skb_ptr = dev_alloc_skb(MAX_BUF_SIZE);
		if (!descptr->skb_ptr) 
		{
		  printk("<No buffer>");
		  break;
	  }
		descptr->buf = cpu_to_le32(pci_map_single(lp->pdev, descptr->skb_ptr->tail, MAX_BUF_SIZE, PCI_DMA_FROMDEVICE));
		descptr->status = 0x8000;
		descptr = descptr->vndescp;
		lp->rx_free_desc++;
		i++;
		//printk("rx_buf_alloc:lp->rx_free_desc:%d \n",lp->rx_free_desc);
		outw(lp->mcr0 | 0x0002, ioaddr);	//Trigger Rx DMA
	}
	if( !descptr->skb_ptr )
		outw(lp->mcr0 | 0x0002, ioaddr);
	lp->rx_insert_ptr = descptr;
}

/* Allocate skb buffer for rx descriptor */
static void rx_buf_alloc(struct r6040_private *lp,struct net_device *dev)
{
	struct r6040_descriptor *descptr;
	int ioaddr = dev->base_addr ;

	//RDC_DBUG
	//printk("rx_buf_alloc()");
	descptr = lp->rx_insert_ptr;
	while(lp->rx_free_desc < RX_DCNT){
		descptr->skb_ptr = dev_alloc_skb(MAX_BUF_SIZE);
		if (!descptr->skb_ptr) 
		{
		  printk("<No buffer>");
		  break;
	  }
		descptr->buf = cpu_to_le32(pci_map_single(lp->pdev, descptr->skb_ptr->tail, MAX_BUF_SIZE, PCI_DMA_FROMDEVICE));
		descptr->status = 0x8000;
		descptr = descptr->vndescp;
		lp->rx_free_desc++;
		//printk("rx_buf_alloc:lp->rx_free_desc:%d \n",lp->rx_free_desc);
		outw(lp->mcr0 | 0x0002, ioaddr);	//Trigger Rx DMA
	}
	if( !descptr->skb_ptr )
		outw(lp->mcr0 | 0x0002, ioaddr);	
	lp->rx_insert_ptr = descptr;
}

/* Status of PHY CHIP */
static int phy_mode_chk(struct net_device *dev)
{
	struct r6040_private *lp = dev->priv;
	int ioaddr = dev->base_addr, phy_dat;

	RDC_DBUG("phy_mode_chk()", 0);

	/* PHY Link Status Check */
	phy_dat = phy_read(ioaddr, lp->phy_addr, 1);
	if (!(phy_dat & 0x4)) return 0x8000;	/* Link Failed, full duplex */

	/* PHY Chip Auto-Negotiation Status */
	phy_dat = phy_read(ioaddr, lp->phy_addr, 1);
	if (phy_dat & 0x0020) {
		/* Auto Negotiation Mode */
		phy_dat = phy_read(ioaddr, lp->phy_addr, 5);
		phy_dat &= phy_read(ioaddr, lp->phy_addr, 4);
		if (phy_dat & 0x140) 
		{
			phy_dat = 0x8000;
#ifdef FORICPLUS			
			phy_write(ioaddr,29,22,0x420);//Set MII0 to support 100Mbps Full duplex
#endif			
		}	
		else{
		 	phy_dat = 0;
#ifdef FORICPLUS			
			phy_write(ioaddr,29,22,0x400);//Set MII0 to support 100Mbps half duplex
#endif			
		} 
	} else {
		/* Force Mode */
		phy_dat = phy_read(ioaddr, lp->phy_addr, 0);
		if (phy_dat & 0x100) phy_dat = 0x8000;
		else phy_dat = 0x0000;
	}

	return phy_dat;
};

/* Read a word data from PHY Chip */
static int phy_read(int ioaddr, int phy_addr, int reg_idx)
{
	int i = 0;

	RDC_DBUG("phy_read()", 0);
	outw(0x2000 + reg_idx + (phy_addr << 8), ioaddr + 0x20);
	do{}while( (i++ < 2048) && (inw(ioaddr + 0x20) & 0x2000) );

	return inw(ioaddr + 0x24);
}

/* Write a word data from PHY Chip */
static void phy_write(int ioaddr, int phy_addr, int reg_idx, int dat)
{
	int i = 0;

	RDC_DBUG("phy_write()", 0);
	outw(dat, ioaddr + 0x28);
	outw(0x4000 + reg_idx + (phy_addr << 8), ioaddr + 0x20);
	do{}while( (i++ < 2048) && (inw(ioaddr + 0x20) & 0x4000) );
}

enum {
	RDC_6040 = 0
};

static struct pci_device_id r6040_pci_tbl[] = {
	{0x17F3, 0x6040, PCI_ANY_ID, PCI_ANY_ID, 0, 0, RDC_6040},
	//{0x1106, 0x3065, PCI_ANY_ID, PCI_ANY_ID, 0, 0, RDC_6040},
	{0,}			/* terminate list */
};
MODULE_DEVICE_TABLE(pci, r6040_pci_tbl);

static struct pci_driver r6040_driver = {
	.name		= "r6040",
	.id_table	= r6040_pci_tbl,
	.probe		= r6040_init_one,
	.remove		= __devexit_p(r6040_remove_one),
};


static int __init r6040_init (void)
{
	RDC_DBUG("r6040_init()", 0);

	printk(version);
	printed_version = 1;

	return pci_module_init (&r6040_driver);
}


static void __exit r6040_cleanup (void)
{
	RDC_DBUG("r6040_cleanup()", 0);
	pci_unregister_driver (&r6040_driver);
}

module_init(r6040_init);
module_exit(r6040_cleanup);


/*
 * Local variables:
 *  compile-command: "gcc -DMODULE -D__KERNEL__ -I/usr/src/linux/net/inet -Wall -Wstrict-prototypes -O6 -c r6040.c `[ -f /usr/include/linux/modversions.h ] && echo -DMODVERSIONS`"
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */

#ifdef FORICPLUS
#define DMZ_GPIO	1
#define RDC3210_CFGREG_ADDR     0x0CF8
#define RDC3210_CFGREG_DATA     0x0CFC
static void process_ioctl(struct net_device *dev, unsigned long* args)
{
	int ioaddr = dev->base_addr;
	
	/* port priority */
	if(args[0]&(1<<31))phy_write(ioaddr,29,19,(phy_read(ioaddr,29,19)|0x2000)); /* port 0 */
	if(args[0]&(1<<29))phy_write(ioaddr,29,19,(phy_read(ioaddr,29,19)|0x0020)); /* port 1 */
	if(args[0]&(1<<27))phy_write(ioaddr,29,20,(phy_read(ioaddr,29,20)|0x2000)); /* port 2 */
	if(args[0]&(1<<25))phy_write(ioaddr,29,20,(phy_read(ioaddr,29,20)|0x0020)); /* port 3 */
	
	/* DMZ LED */
	
	{	
		unsigned int val;

        val = 0x80000000 | (7 << 11) | ((0x48));
		outl(val, RDC3210_CFGREG_ADDR);
		udelay(10);
        val = inl(RDC3210_CFGREG_DATA);
        
        val |= (0x1 << DMZ_GPIO);
		outl(val, RDC3210_CFGREG_DATA);
		udelay(10);

        val = 0x80000000 | (7 << 11) | ((0x4C));
		outl(val, RDC3210_CFGREG_ADDR);
		udelay(10);
        val = inl(RDC3210_CFGREG_DATA);
        if(args[0]&(1<<23))	/* DMZ enabled */
			val &= ~(0x1 << DMZ_GPIO);	/* low activated */
		else val |= (0x1 << DMZ_GPIO);
		outl(val, RDC3210_CFGREG_DATA);
		udelay(10);
	}
        
	
}	
#endif /* FORICPLUS */