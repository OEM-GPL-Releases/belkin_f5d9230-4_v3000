/*******************************************************
 * CFI Flash - AMD Standard Command Set:               *
 *                                                     *
 * (C) 2004 Gemtek                                     *
 *                                                     *
 * 2004.05.21	Dante Su (dante_su@gemtek.com.tw)      *
 *******************************************************/
 
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/io.h>

#include <linux/param.h>
#include <linux/sched.h>
#include <linux/timer.h>

#include "flashdrv.h"
#include "cmdset_amd.h"

extern struct flashinfo		dev;

static int __toggle_bit(volatile UINT16 *memptr);


static int __toggle_bit(volatile UINT16 *memptr)
{	
	UINT16	prev, curr;
			
	prev = *memptr & BIT6;
	
	while(1)
	{
		curr = *memptr & BIT6;
		
		if(curr == prev)
			break;
		else	
			prev = curr;
	}
	
	return 0;
}

int cmdset_amd_reset(void)
{	
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;
	
	if(cmdset == NULL)	return -1;
		
	*memptr = cmdset->reset;
		
	return __toggle_bit(memptr);
}

int cmdset_amd_unlock_bypass(void)
{
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;
	
	memptr[cmdset->addr1] = cmdset->unlock1;
	memptr[cmdset->addr2] = cmdset->unlock2;
	memptr[cmdset->addr1] = 0x0020;
	
	return __toggle_bit(memptr);
}

int cmdset_amd_unlock_bypass_reset(void)
{
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	
	*memptr = 0x0090;
	*memptr = 0x0000;
	
	return __toggle_bit(memptr);
}

int cmdset_amd_write_std(int sector, int offset, const void *data, int numbytes)
{					
	const UINT16		*src;
	volatile UINT16		*dst;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(sector);
	struct command_set	*cmdset = dev.cmdset;				

	PDEBUG("## AMD style standard write\n");

	src = data;
	dst = memptr + (offset / 2);			
	
	if((offset | numbytes) & 1)
		PMESSAGE("WARNING : offset or numbytes is ODD.\n");
	
	// Enter Unlock Bypass Mode if possible.
	if(dev.config & FLASH_CONF_UNLOCKBYPASS)
		cmdset_amd_unlock_bypass();
	
	PDEBUG("## we're going to write %d bytes into sector %d\n", numbytes, sector);
	
	while(numbytes)
	{	
		int	retry;	
		
		for(retry = 32; retry; --retry)
		{
			if(!(dev.config & FLASH_CONF_UNLOCKBYPASS))
			{
				memptr[cmdset->addr1] = cmdset->unlock1;
				memptr[cmdset->addr2] = cmdset->unlock2;
			}
		
			memptr[cmdset->addr1] = cmdset->write;
		
			*dst = *src;
						
			if(!__toggle_bit(memptr) && *dst == *src)
				break;
		}
		
		if(!retry)	break;
						
		++dst; ++src;
		numbytes -= 2;		
	}
	
	if(numbytes)	
		PERROR("\t-- fail to write into sector %d, %d bytes left, desired[%04X] got[%04X]\n", sector, numbytes, *src, (*dst & 0xFFFF));	
	else
		PDEBUG("\t-- write success.\n");	
	
	// Exit Unlock Bypass Mode
	if(dev.config & FLASH_CONF_UNLOCKBYPASS)
		cmdset_amd_unlock_bypass_reset();		
	
	return numbytes ? -1 : (int)((int)src - (int)data);
}

int cmdset_amd_write_page(int sector, int offset, const void *data, int numbytes)
{				
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(sector);
	struct command_set	*cmdset = dev.cmdset;					
	
	int			i, retry, written = 0;
	UINT16			wc;
	const UINT16		*src;
	volatile UINT16		*dst;
	
	if(dev.psize == 0)	return -1;
	
	PDEBUG("## AMD style page mode write, page size = %d Bytes\n", dev.psize);
		
	src = data;
	dst = memptr + (offset / 2);
	
	if((offset | numbytes) & 1)
		PMESSAGE("WARNING : offset or numbytes is ODD.\n");
	
	while(numbytes)
	{					
		wc = (numbytes > dev.psize ? dev.psize : numbytes) / 2;
		
		for(retry = 32; retry; --retry)
		{		
			memptr[cmdset->addr1] = cmdset->unlock1;
			memptr[cmdset->addr2] = cmdset->unlock2;
			*memptr		      = 0x0025;
			*memptr               = wc - 1;
			
			for(i = 0; i < wc; ++i)
				*(dst++) = *(src++);
				
			*memptr		      = 0x0029;
						
			if(!__toggle_bit(memptr) && *(dst - 1) == *(src - 1))
				break;
		}
		
		if(!retry)	break;
							
		numbytes -= wc * 2;
		written  += wc * 2;
	}
	
	if(numbytes)	
		PERROR("\t-- fail to write into sector %d, %d bytes left.\n", sector, numbytes);	
	else	
		PDEBUG("\t-- write success.\n");	
		
	return numbytes ? -1 : written;
}

int cmdset_amd_erase_chip(void)
{
	int	retry;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;			
	
	for(retry = 32; retry; --retry)
	{
		cmdset_amd_reset();
		
		memptr[cmdset->addr1] = cmdset->unlock1;
		memptr[cmdset->addr2] = cmdset->unlock2;
		memptr[cmdset->addr1] = 0x0080;
	
		memptr[cmdset->addr1] = cmdset->unlock1;
		memptr[cmdset->addr2] = cmdset->unlock2;
		memptr[cmdset->addr1] = cmdset->erase_chip;
	
		if(!__toggle_bit(memptr) && (*memptr & 0xFFFF) == 0xFFFF)
			break;
	}		
	
	if(retry)	
	{	
		PDEBUG("## Erase chip successfully.\n");
		return 0;
	} 
	else
	{
		PERROR("## Error : fail to erase chip.\n");	
		return -1;
	}
}

int cmdset_amd_erase_sector(int sector)
{
	int	retry;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(sector);
	struct command_set	*cmdset = dev.cmdset;		
		
	for(retry = 32; retry; --retry)
	{
		cmdset_amd_reset();
		
		memptr[cmdset->addr1] = cmdset->unlock1;
		memptr[cmdset->addr2] = cmdset->unlock2;
		memptr[cmdset->addr1] = 0x0080;
	
		memptr[cmdset->addr1] = cmdset->unlock1;
		memptr[cmdset->addr2] = cmdset->unlock2;
	
		*memptr = cmdset->erase_sector;		
	
		if(!__toggle_bit(memptr) && (*memptr & 0xFFFF) == 0xFFFF)
			break;
	}		
	
	if(retry)	
	{
		PDEBUG("## Erase sector %d successfully.\n", sector);
		return 0;
	}
	else
	{
		PERROR("## Error : fail to erase sector %d.\n", sector);
		return -1;
	}	
}

int cmdset_amd_erase_suspend(void)
{
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;		
		
	*memptr = cmdset->suspend;
	
	return __toggle_bit(memptr);
}

int cmdset_amd_erase_resume(void)
{
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;		
		
	*memptr = cmdset->resume;
	
	return __toggle_bit(memptr);
}
