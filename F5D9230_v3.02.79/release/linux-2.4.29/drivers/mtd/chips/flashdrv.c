/*******************************************************
 * CFI Flash - Common Flash Driver API:                *
 *                                                     *
 * (C) 2004 Gemtek                                     *
 *                                                     *
 * 2004.05.21	Dante Su (dante_su@gemtek.com.tw)      *
 *******************************************************/
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <asm/delay.h>

#include <linux/param.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/mtd/map.h>

#include "flashdrv.h"
#include "cmdset_amd.h"
#include "cmdset_intel.h"

/*=============================================================*/
/*       Static Function Declaration                           */
/*=============================================================*/

static void __load_flash_id(void);

// Dante : we use CFI query to determine the command set
static void __load_flash_cmdset(struct cfiquery *q);
static void __load_flash_conf(struct cfiquery *q);
static void __init_flash_memory_layout(struct cfiquery *q);
static int  __do_cfi_query(struct cfiquery *q);

/*=============================================================*/
/*       Variables Declaration                                 */
/*=============================================================*/
struct flashinfo		dev;

// Dante : It looks like that sector mode in SST29VF160 doesn't work well, so we use block mode.
//         (It means that we use the command for Block Erase to be our Sector Erase command.) 
static struct command_set cmdsets[] = 
{
	//     cmdset id,       addr1,  addr2,  unlock1, unlock2, reset, write, e_chip, e_sector, e_suspend, e_resume
	{ CMDSET_AMD_STD,       0x555,  0x2AA,     0xAA,    0x55,  0xF0,  0xA0,   0x10,     0x30,      0xB0,     0X30,
	  cmdset_amd_reset, cmdset_amd_write_std, cmdset_amd_write_page, cmdset_amd_erase_chip, cmdset_amd_erase_sector, 
	  cmdset_amd_erase_suspend, cmdset_amd_erase_resume,
	},	
	 	 
	//     cmdset id,       addr1,  addr2,  unlock1, unlock2, reset, write, e_chip, e_sector, e_suspend, e_resume
	{ CMDSET_SST_STD,      0x5555, 0x2AAA,     0xAA,    0x55,  0xF0,  0xA0,   0x10,     0x50,      0xB0,     0X30,
	  cmdset_amd_reset, cmdset_amd_write_std, cmdset_amd_write_page, cmdset_amd_erase_chip, cmdset_amd_erase_sector, 
	  cmdset_amd_erase_suspend, cmdset_amd_erase_resume,
	},
	
	//       cmdset id,  addr1, addr2, unlock1, unlock2, reset, write, e_chip, e_sector, e_suspend, e_resume
	{ CMDSET_INTEL_STD,      0,     0,       0,       0,  0xFF,  0x40,      0,     0xD0,         0,        0,
	  cmdset_intel_reset, cmdset_intel_write_std, NULL, NULL, cmdset_intel_erase_sector, 
	  NULL, NULL,
	},
	
	{0}
};

/*=============================================================*/
/*       Function Implementation                               */
/*=============================================================*/

static volatile void *fptr = NULL;	/* Flash ROM Pointer */

static void rdc3210_init(struct map_info *map)
{
#define RDC3210_CFGREG_ADDR	0x0CF8
#define RDC3210_CFGREG_DATA	0x0CFC

	UINT32	val;
	
	val = BIT31 | (7 << 11) | ((0x42) & 0xFC);
	outl(val, RDC3210_CFGREG_ADDR);
	udelay(10);
	val = inl(RDC3210_CFGREG_DATA);
	val |= (0x87FF << 16);
	outl(val, RDC3210_CFGREG_DATA);
	udelay(10);
	
	fptr = map->map_priv_1;
}

volatile UINT8 *flashdrv_get_memptr(int sector)
{	
	//return (volatile UINT8 *)(dev.sectors[sector].addr + FLASH_BASE_ADDR);
	return (volatile UINT8 *)(dev.sectors[sector].addr + ((UINT32)fptr));
}

int flashdrv_init(struct map_info *map)
{
	struct cfiquery	q;
	
	rdc3210_init(map);
	
	memset(&q, 0, sizeof(struct cfiquery));
	memset(&dev, 0, sizeof(struct flashinfo));
			
	__load_flash_cmdset(&q);
	__load_flash_id();
	__load_flash_conf(&q);

	flashdrv_reset();

	return 0;
}

int flashdrv_get_blocknum(void)
{
	return dev.blknum;
}

int flashdrv_get_block_addr(int blk)
{
	return dev.blocks[blk].addr;
}

int flashdrv_get_block_sectorsz(int blk)
{
	return dev.blocks[blk].secsz;
}

int flashdrv_get_block_sectornum(int blk)
{
	return dev.blocks[blk].secnum;
}

int flashdrv_get_sectornum(void)
{
	return dev.sectornum;
}

int flashdrv_get_sector_size(int sector)
{
	return dev.sectors[sector].size;
}

int flashdrv_get_sector_addr(int sector)
{
	return dev.sectors[sector].addr;
}

int flashdrv_get_size(void)
{
	return dev.size;
}

int flashdrv_get_sector(int addr)
{
	int	idx, curraddr;
		
	curraddr = 0;
	for(idx = 0; idx < dev.sectornum; ++idx)
	{
		curraddr += dev.sectors[idx].size;
		
		if(curraddr > addr)	return idx;
	}
	
	return -1;
}

int flashdrv_reset(void)
{	
	struct command_set	*cmdset = dev.cmdset;
	
	// It should never be NULL
	return (*(cmdset->fp_reset))();
}

int flashdrv_read(int sector, int offset, void *buffer, int numbytes)
{
	int		len;
	UINT16		*dst;
	volatile UINT16	*src;
	
	len = numbytes / 2;
	dst = buffer;
	src = (volatile UINT16 *)(flashdrv_get_memptr(sector) + offset);
	
	while(len--)
		*(dst++) = *(src++);
		
	// Odd
	if(numbytes & 1)
	{
		PERROR("# Warning: odd byte\n");
		*(UINT8 *)dst = *(UINT8 *)src;
	}

	return numbytes;
}

int flashdrv_write(int sector, int offset, const void *data, int numbytes)
{			
	int			ret = 0;
	struct command_set	*cmdset = dev.cmdset;
	
	if((dev.config & FLASH_CONF_PAGEMODE) && cmdset->fp_write_page)
		ret |= (*(cmdset->fp_write_page))(sector, offset, data, numbytes);
	else
		ret |= (*(cmdset->fp_write_std))(sector, offset, data, numbytes);
		
	flashdrv_reset();
	
	return ret;
}

int flashdrv_erase_sector(int sector)
{	
	int			ret = 0;
	struct command_set	*cmdset = dev.cmdset;		
	
	if(cmdset->fp_erase_sector == NULL)
	{
		PERROR("# Erase Sector is not supported\n");
		return -1;
	}

	ret |= (*(cmdset->fp_erase_sector))(sector);
	
	flashdrv_reset();
	
	return ret;
}

int flashdrv_erase_suspend(void)
{	
	struct command_set	*cmdset = dev.cmdset;
	
	if(cmdset->fp_erase_suspend == NULL)
	{
		PERROR("# Erase Suspend is not supported\n");
		return -1;
	}
		
	return (*(cmdset->fp_erase_suspend))();	
}

int flashdrv_erase_resume(void)
{	
	struct command_set	*cmdset = dev.cmdset;
	
	if(cmdset->fp_erase_resume == NULL)
	{
		PERROR("# Erase Resume is not supported\n");
		return -1;
	}
		
	return (*(cmdset->fp_erase_resume))();	
}

static void __load_flash_cmdset(struct cfiquery *q)
{	
	struct command_set	*cmdset = cmdsets;
		
	for(cmdset = cmdsets; cmdset->id != CMDSET_UNKNOWN; ++cmdset)
	{
		// 1. Specify the current command set
		dev.cmdset = cmdset;
				
		// 2. If CFI query return success, then it should be the right command set
		if(__do_cfi_query(q) == 0 && q->cmdset == cmdset->id)
		{
			char	*msg = NULL;

			switch(cmdset->id)
			{				
				case CMDSET_AMD_STD:
					msg = "AMD/Fujitsu Standard";
					break;
				case CMDSET_SST_STD:
					msg = "SST Standard";
					break;
				case CMDSET_INTEL_STD:
					msg = "Intel Standard";
					break;
				case CMDSET_MITSUBISHI_STD:				
					msg = "Mitsubishi Standard";
					break;
			}
		
			PMESSAGE("## Decide to use %s command set.\n", msg);			
			return;
		}
	}
		
	PERROR("## Error : No suitable command set is found. Try default cmdset-AMD STD\n");
	dev.cmdset = cmdset = cmdsets;
	flashdrv_reset();
}

static void __load_flash_id(void)
{
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);	
	struct command_set	*cmdset = dev.cmdset;
	
	flashdrv_reset();
		
	if(cmdset->unlock1)	memptr[cmdset->addr1] = cmdset->unlock1;
	if(cmdset->unlock2)	memptr[cmdset->addr2] = cmdset->unlock2;
	memptr[cmdset->addr1] = 0x90;
	
	dev.mid = memptr[0];
	dev.did = memptr[1];
	
	flashdrv_reset();

	PMESSAGE("## MFG ID = 0x%04X, DEV ID = 0x%04X\n", dev.mid, dev.did);
}

static void __load_flash_conf(struct cfiquery *q)
{			
	// Vendor Specific Function Switch
	switch(dev.mid)
	{
		case MID_AMD:
		case MID_FUJITSU:
			PMESSAGE("## Enable Unlock Bypass Mode.\n");
			dev.config |= FLASH_CONF_UNLOCKBYPASS;
			break;
		default:		
			break;			
	}
	
	// Again, execute the CFI query to get the device information
	__do_cfi_query(q);
	
	// Dante : Since it's not guaranteed that CFI-PRI query for boot-style would be supported in every AMD family flashes,
	//         so I have wrote the following code to identify the boot style after cfi query
	switch(dev.did)
	{
		case DID_AM29DL800T:
		case DID_AM29LV800T:		
		case DID_AM29LV320T:	
		case DID_MX29LV320T:
			q->boot = FLASH_BS_TBOOT;
			break;
			
		case DID_AM29DL800B:
		case DID_AM29LV800B:
		case DID_AM29LV400B:		
		case DID_AM29LV320B:
		case DID_MX29LV320B:
		case DID_AT49BV322A:		
			q->boot = FLASH_BS_BBOOT;
			break;
			
		case DID_AM29LV320M:
			// Dante : The boot sector flag has been setup in CFI query.
			break;
			
		// Because of the CFI issue in MXIC, so we hardcode the memory layout here.
		case DID_AM29LV160B:			
			// Dante : The information of the memory layout in CFI is wrong.
			q->block_num = 4;
			q->blocks[0].sector_num  = 1;
			q->blocks[0].sector_size = 0x00004000;
			q->blocks[1].sector_num  = 2;
			q->blocks[1].sector_size = 0x00002000;
			q->blocks[2].sector_num  = 1;
			q->blocks[2].sector_size = 0x00008000;
			q->blocks[3].sector_num  = 31;
			q->blocks[3].sector_size = 0x00010000;
			q->boot = FLASH_BS_BBOOT;
			break;
			
		case DID_AM29LV160T:
			q->block_num = 4;
			q->blocks[0].sector_num  = 31;
			q->blocks[0].sector_size = 0x00010000;
			q->blocks[1].sector_num  = 1;
			q->blocks[1].sector_size = 0x00008000;
			q->blocks[2].sector_num  = 2;
			q->blocks[2].sector_size = 0x00002000;
			q->blocks[3].sector_num  = 1;
			q->blocks[3].sector_size = 0x00004000;
			q->boot = FLASH_BS_TBOOT;
			break;
			
		case DID_SST39VF160:
		case DID_SST39VF1601:
		case DID_SST39VF1602:
			q->boot = FLASH_BS_UNIFORM;
			// Dante : The information of the memory layout in CFI is wrong.
			q->block_num = 1;
			q->blocks[0].sector_num  = 32;
			q->blocks[0].sector_size = 0x00010000;
			break;
			
		case DID_SST39VF320:
		case DID_SST39VF3201:
		case DID_SST39VF3202:
			q->boot = FLASH_BS_UNIFORM;
			// Dante : The information of the memory layout in CFI is wrong.
			q->block_num = 1;
			q->blocks[0].sector_num  = 64;
			q->blocks[0].sector_size = 0x00010000;
			break;

		default:
			q->boot = FLASH_BS_BBOOT;
			break;
	}		
		
	dev.config |= (q->boot & FLASH_CONF_BOOTSECTOR);
	dev.config |= (q->psize ? FLASH_CONF_PAGEMODE : 0);
	
	dev.psize  = q->psize;	
		
	// Initiallize the flash memory layout
	__init_flash_memory_layout(q);
}

static int __do_cfi_query(struct cfiquery *q)
{
	int			i;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;		
	
	flashdrv_reset();
	
	// ------ Issue CFI command	
	switch(cmdset->id)
	{
		case CMDSET_SST_STD:
			memptr[cmdset->addr1] = cmdset->unlock1;
			memptr[cmdset->addr2] = cmdset->unlock2;
			break;
			
		default:
			break;
	}
	memptr[cmdset->addr1] = 0x0098;
	// -------------------------
		
	if(memptr[0x10] != 'Q' || memptr[0x11] != 'R' || memptr[0x12] != 'Y')
	{
		PERROR("## Error : CFI Query fail, current cmdset = %d, \n", cmdset->id);
		return -1;
	}

	if(q == NULL)
	{
		PDEBUG("## WARNING : CFI Query struct is NULL, abort the query\n");
		flashdrv_reset();
		return 0;
	}
	
	memset(q, 0, sizeof(struct cfiquery));
	
	q->cmdset      = (memptr[0x14] << 8) | memptr[0x13];
	
	// Dante : This query is just used to determine the command set
	if(dev.mid == 0 || dev.did == 0)
		return 0;
	
	q->device_size = (1 << (memptr[0x27]));				
	q->block_num   = memptr[0x2C];	
	for(i = 0; i < q->block_num; ++i)
	{
		q->blocks[i].sector_num  = ((memptr[0x2E + (i * 4)] << 8) | memptr[0x2D + (i * 4)]) + 1;
		q->blocks[i].sector_size = ((memptr[0x30 + (i * 4)] << 8) | memptr[0x2F + (i * 4)]) * 256;
	}	

	// Verify if there is a valid PRI Query	table
	if(memptr[0x15] == 0)		
		return 0;
		
	if(memptr[memptr[0x15]] != 'P' || memptr[memptr[0x15] + 1] != 'R' || memptr[memptr[0x15] + 2] != 'I')
		return 0;
	
	// Do Vendor Specific PRI Query	
	switch(dev.mid)
	{
		case MID_AMD:
		case MID_FUJITSU:
		case MID_MXIC:
			// Dante : Always use 32 Byte page memory
			q->psize = memptr[0x4C] ? 32 : 0;
			// Dante : Since it's not guaranteed that this PRI query would be supported in every AMD family flashes,
			//         so I have wrote a device id list to identify the boot style after this function.
			switch(memptr[0x4F])
			{				
				case 0x0002:
					q->boot = FLASH_BS_BBOOT;
					break;
					
				case 0x0003:
					q->boot = FLASH_BS_TBOOT;
					break;
							
				case 0x0004:
				case 0x0005:
					q->boot = FLASH_BS_UNIFORM;
					break;
				default:
					q->boot = FLASH_BS_BBOOT;
					break;
			}			
			break;
			
		default:
			break;
	}		
		
	flashdrv_reset();
	
	return 0;
}

static void __init_flash_memory_layout(struct cfiquery *q)
{	
	int	sidx = 0, addr = 0;
	int	i, j, bi, sz, ns, reverse;
		
	switch(q->boot)
	{
		case FLASH_BS_BBOOT:
			reverse = q->blocks[0].sector_size > q->blocks[q->block_num - 1].sector_size;
			break;
			
		case FLASH_BS_TBOOT:
			reverse = q->blocks[0].sector_size < q->blocks[q->block_num - 1].sector_size;
			break;
			
		case FLASH_BS_UNIFORM:		
		default:
			reverse = 0;
			break;
	}
	
	bi	      = 0;
	addr          = 0;
	dev.size      = 0;
	dev.sectornum = 0;
	dev.blknum    = q->block_num;
	
	if(reverse)
	{				
		for(i = q->block_num - 1; i >= 0; --i)
		{						
			ns = q->blocks[i].sector_num;
			sz = q->blocks[i].sector_size;
						
			dev.blocks[bi].addr   = addr;
			dev.blocks[bi].secsz  = sz;
			dev.blocks[bi].secnum = ns;
			++bi;
			
			dev.sectornum += ns;		
			dev.size      += ns * sz;
		
			for(j = 0; j < ns; ++j, ++sidx)
			{
				dev.sectors[sidx].addr = addr;
				dev.sectors[sidx].size = sz;
			
				addr += sz;							
			}
		}
	}
	else
	{				
		for(i = 0; i < q->block_num; ++i)
		{						
			ns = q->blocks[i].sector_num;
			sz = q->blocks[i].sector_size;
			
			dev.blocks[bi].addr   = addr;
			dev.blocks[bi].secsz  = sz;
			dev.blocks[bi].secnum = ns;
			++bi;
			
			dev.sectornum += ns;
			dev.size      += ns * sz;
		
			for(j = 0; j < ns; ++j, ++sidx)
			{
				dev.sectors[sidx].addr = addr;
				dev.sectors[sidx].size = sz;
			
				addr += sz;							
			}
		}
	}
	
	if(dev.sectornum > FLASHDRV_MAX_SECTOR_NUM)
		PERROR("## Error : The sector number of this flash is too big!!\n");			
		
	if(dev.size != q->device_size)
	{
		PERROR("## Error : dev.size = %d, q.device_size = %d\n", dev.size, q->device_size);
		PERROR("##         Are you using some kind of SST flash? \nPlease setup memory info manually\n");	
	}
	
	PMESSAGE("Total size = %d MB\n", dev.size / 1024 / 1024);
		
#if FLASHDRV_DEBUG	
//#if 1
	switch(q->boot)
	{
		case FLASH_BS_BBOOT:
			PMESSAGE("Boot Style: Bottom\n");		break;			
		case FLASH_BS_TBOOT:
			PMESSAGE("Boot Style: Top\n");		break;			
		case FLASH_BS_UNIFORM:		
			PMESSAGE("Boot Style: Uniform\n");	break;
	}
	for(i = 0; i < sidx; ++i)
	{
		PMESSAGE("# sector %d - addr = 0x%08X, size = 0x%08X\n", 
					i, dev.sectors[i].addr, dev.sectors[i].size);
	}
#endif
}
