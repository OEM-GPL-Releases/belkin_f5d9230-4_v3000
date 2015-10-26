/*******************************************************
 * CFI Flash - Intel Standard Command Set:             *
 *                                                     *
 * (C) 2004 Gemtek                                     *
 *                                                     *
 * 2004.05.21	Dante Su (dante_su@gemtek.com.tw)      *
 *******************************************************/
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/sched.h>
#include <linux/timer.h>

#include <asm/io.h>
#include <asm/delay.h>

#include "flashdrv.h"
#include "cmdset_intel.h"

extern struct flashinfo		dev;

#define CMD_TIMEOUT		0x1FFFFFFF

static int __status_check(volatile UINT16 *memptr);

static int __sector_lock(volatile UINT16 *memptr);
static int __sector_unlock(volatile UINT16 *memptr);

static int __status_check(volatile UINT16 *memptr)
{	
	int	timeo;
	UINT16	stat;		
	
	// Wait for BIT7
	for(timeo = CMD_TIMEOUT; timeo; --timeo)
	{
		if((stat = *memptr) & BIT7)	break;
	}
	
	// Timeout
	if(!timeo)
	{
		PERROR("# Command Timeout\n");
		return -1;
	}
	
	// Error Check		
	if(stat & (BIT5 | BIT4))
	{
		PERROR("# Found Errors: Status Bit = 0x%04X\n", stat);
		
		if(stat & BIT5)	PERROR("# Erase Error,");
		if(stat & BIT4)	PERROR("# Write Error,");
		if(stat & BIT3)	PERROR("# VPP Low Detected,");
		if(stat & BIT1)	PERROR("# Block Clock Detected,");
		
		PERROR("\n");
		
		// Clear Status Bit
		*memptr = 0x50;
		
		return -1;
	}
				
	return 0;
}

int cmdset_intel_reset(void)
{	
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(0);
	struct command_set	*cmdset = dev.cmdset;
	
	if(cmdset == NULL)	return -1;
		
	*memptr = cmdset->reset;
	
	udelay(1);
				
	return 0;
}

int cmdset_intel_write_std(int sector, int offset, const void *data, int numbytes)
{					
	const UINT16		*src;
	volatile UINT16		*dst;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(sector);
	struct command_set	*cmdset = dev.cmdset;				

	PDEBUG("## Intel style standard write\n");

	src = data;
	dst = memptr + (offset / 2);
	
	if((offset | numbytes) & 1)
		PMESSAGE("WARNING : offset or numbytes is ODD.\n");
		
	__sector_unlock(memptr);
	
	PDEBUG("## we're going to write %d bytes into sector %d\n", numbytes, sector);
	
	while(numbytes)
	{
		*dst = cmdset->write;
		*dst = *src;
		
		if(__status_check(memptr))
			break;

		++dst; ++src;
		numbytes -= 2;
	}
	
	if(numbytes)
		PERROR("\t-- fail to write into sector %d, %d bytes left\n", sector, numbytes);	
	else
		PDEBUG("\t-- write success.\n");			
	
	__sector_lock(memptr);
	
	return numbytes ? -1 : (int)((int)src - (int)data);
}

int cmdset_intel_erase_sector(int sector)
{	
	int			ret;
	volatile UINT16		*memptr = (volatile UINT16 *)flashdrv_get_memptr(sector);
	struct command_set	*cmdset = dev.cmdset;		
	
	__sector_unlock(memptr);
	
	// Erase
	*memptr = 0x20;
	*memptr = cmdset->erase_sector;
	
	if(!(ret = __status_check(memptr)))
		PDEBUG("## Erase sector %d success.\n", sector);
	else
		PERROR("## Erase sector %d fail.\n", sector);
		
	__sector_lock(memptr);		
		
	return ret;
}

static int __sector_lock(volatile UINT16 *memptr)
{
	int	ret;		
	
	// Lock
	*memptr = 0x60;
	*memptr = 0x01;
	
	if(!(ret = __status_check(memptr)))
		PDEBUG("## Lock sector success.\n");
	else
		PERROR("## Lock sector fail.\n");
		
	return ret;
}

static int __sector_unlock(volatile UINT16 *memptr)
{
	int	ret;		
	
	// Unlock
	*memptr = 0x60;
	*memptr = 0xD0;
	
	if(!(ret = __status_check(memptr)))
		PDEBUG("## Unlock sector success.\n");
	else
		PERROR("## Unlock sector fail.\n");
		
	return ret;
}
