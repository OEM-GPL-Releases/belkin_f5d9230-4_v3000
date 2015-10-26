/*******************************************************************
 * CFI Flash                                                       *
 *                                                                 *
 * Common Flash Interface probe code.                              *
 *                                                                 *
 *                                                (C) 2004 Gemtek  * 
 *                    2004.05.21 Dante Su (dante_su@gemtek.com.tw) *
 *                                                                 *
 * Update History:                                                 *
 * 1. 2004.05.21 Dante Su                                          *
 *    - initial release                                            *
 * 2. 2005.06.03 Dante Su                                          *
 *    - support both spinlock and semaphore (default is semaphore) *
 *******************************************************************/

/* Dante: You should use only one of these lock scheme,            *
 *        if you defined both of them, only semaphore would be use */
#define CFI_LOCK_SEMAPHORE			1
//#define CFI_LOCK_SPINLOCK			1


#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <asm/byteorder.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/interrupt.h>

#include <linux/mtd/map.h>

#include "flashdrv.h"

#if !defined(CFI_LOCK_SPINLOCK) && !defined(CFI_LOCK_SEMAPHORE)
#define CFI_LOCK_SEMAPHORE			1
#endif

#if CFI_LOCK_SPINLOCK		/* spin_lock version */

static spinlock_t	cfilock;
static unsigned long	irqflags;
#define __cfi_lock_init()	spin_lock_init(&cfilock)
#define __cfi_lock_lock()	spin_lock_irqsave(&cfilock, irqflags)
#define __cfi_lock_unlock()	spin_unlock_irqrestore(&cfilock, irqflags)

#elif CFI_LOCK_SEMAPHORE	/* semaphore version */

#include <asm/semaphore.h>	
static DECLARE_MUTEX(cfilock);
#define __cfi_lock_init()	init_MUTEX(&cfilock)
#define __cfi_lock_lock()	down_interruptible(&cfilock)
#define __cfi_lock_unlock()	up(&cfilock)

#endif				/* end of spin_lock, semaphores */

// loff_t  == long long == 64 bits
static int __cfidrv_read (struct mtd_info *mtd, loff_t addr, size_t len, size_t *rlen, u_char *buf)
{
	UINT32	src = (UINT32)(addr & 0xFFFFFFFF);

	__cfi_lock_lock();

	if(rlen != NULL)
		*rlen = flashdrv_read(0, src, buf, len);
	else
		flashdrv_read(0, src, buf, len);

	__cfi_lock_unlock();
	return 0;
}

static int __cfidrv_erase(struct mtd_info *mtd, struct erase_info *e)
{
	int	begin, end, err;
	
	if (e->addr >= mtd->size || ((e->len + e->addr) > mtd->size))
		return -EINVAL;
	
	begin = flashdrv_get_sector(e->addr);
	end   = flashdrv_get_sector(e->addr + e->len - 1);	// count from 0
	if(end < 0)	end = begin;
	
	PDEBUG("# __cfidrv_erase: %d, %d; [%d, %d]\n", begin, end, e->addr, e->addr + e->len);
	
	__cfi_lock_lock();
	
	err = 0;
	while(begin <= end)
	{
		err |= flashdrv_erase_sector(begin);
		if(err)	break;
		++begin;
	}
	
	__cfi_lock_unlock();
	
	if(err)
		PERROR("## Error: erase sector (%d) fail\n", begin);
	
	e->state = MTD_ERASE_DONE;
	if (e->callback)
		e->callback(e);
		
	return err;
}

// loff_t  == long long == 64 bits
static int __cfidrv_write(struct mtd_info *mtd, loff_t addr, size_t len, size_t *wlen, const u_char *buf)
{
	UINT32	dst = (UINT32)(addr & 0xFFFFFFFF);
	int	sector = 0, maxlen = 0, offset = 0, wrote = 0;
		
	if (dst >= mtd->size || ((len + dst) > mtd->size))
		return -EINVAL;
	
	__cfi_lock_lock();
	
	*wlen = 0;
	
	while(len > 0)
	{
		sector = flashdrv_get_sector(dst);
		maxlen = len > flashdrv_get_sector_size(sector) ? flashdrv_get_sector_size(sector) : len;
		offset = dst - flashdrv_get_sector_addr(sector);
		
		PDEBUG("# __cfidrv_write: sector = %d, offset = %08X, maxlen = %d\n", sector, offset, maxlen);
		
		wrote  = flashdrv_write(sector, offset, buf, maxlen);
		if(wrote < 0)	break;
		
		buf   += wrote;
		dst   += wrote;
		*wlen += wrote;
		len    = (len <= wrote) ? 0 : (len - wrote);			
	}
	
	__cfi_lock_unlock();
	
	if(len > 0 || wrote < 0)
		PERROR("## Error: write sector (%d) fail\n", sector);
		
	return 0;
}

struct mtd_info *cfi_probe(struct map_info *map)
{
	int		i;
	struct mtd_info	*mtd;
	
	__cfi_lock_init();
	
	mtd = kmalloc(sizeof(struct mtd_info), GFP_KERNEL);
	if (!mtd)
	{
		PERROR("Failed to allocate memory for MTD device\n");		
		return NULL;
	}
	memset(mtd, 0, sizeof(struct mtd_info));
	
	flashdrv_init(map);	
	
	mtd->priv  = map;
	mtd->name  = map->name;
	mtd->type  = MTD_NORFLASH;
	mtd->flags = MTD_CAP_NORFLASH;
		
	mtd->size  = flashdrv_get_size();
	mtd->read  = __cfidrv_read;
	mtd->erase = __cfidrv_erase;
	mtd->write = __cfidrv_write;

	mtd->numeraseregions = flashdrv_get_blocknum();
	mtd->eraseregions    = kmalloc(sizeof(struct mtd_erase_region_info) * mtd->numeraseregions, GFP_KERNEL);	
	for(i = 0; i < mtd->numeraseregions; ++i)
	{
		mtd->eraseregions[i].offset    = flashdrv_get_block_addr(i);
		mtd->eraseregions[i].erasesize = flashdrv_get_block_sectorsz(i);
		mtd->eraseregions[i].numblocks = flashdrv_get_block_sectornum(i);
		
		if(mtd->erasesize < mtd->eraseregions[i].erasesize)
			mtd->erasesize = mtd->eraseregions[i].erasesize;
	}
	
	MOD_INC_USE_COUNT;
	return mtd;
}

static struct mtd_chip_driver cfi_chipdrv = 
{
	probe:	cfi_probe,
	name:	"cfi_probe",
	module:	THIS_MODULE
};

int __init cfi_probe_init(void)
{
	register_mtd_chip_driver(&cfi_chipdrv);
	return 0;
}

static void __exit cfi_probe_exit(void)
{
	unregister_mtd_chip_driver(&cfi_chipdrv);
}

module_init(cfi_probe_init);
module_exit(cfi_probe_exit);

MODULE_AUTHOR("Dante Su <dante_su@gemtek.com.tw>");
