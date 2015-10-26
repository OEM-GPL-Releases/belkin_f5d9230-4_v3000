/***************************************************************/
/* Dante Su  2003.12.29                                        */
/***************************************************************/

#ifndef _FLASHDRV_H
#define _FLASHDRV_H

// Dante : debug flag must be defined before the header to be included
#define FLASHDRV_DEBUG			0

#include "flashdrv_param.h"

#define FLASHDRV_MAX_BLOCK_NUM		8
#define FLASHDRV_MAX_SECTOR_NUM		128

/***************************************************************/
/*        Flash manufacturing ID                               */
/***************************************************************/

#define MID_AMD		0x0001
#define MID_FUJITSU	0x0004
#define MID_ATMEL	0x001F
#define MID_SST		0x00BF
#define MID_MXIC	0x00C2

/***************************************************************/
/*        Flash Device ID                                      */
/***************************************************************/

/* A list of device ID's - add others as needed */
#define DID_AM29DL800T	0x224A
#define DID_AM29DL800B	0x22CB
#define DID_AM29LV800T	0x22DA
#define DID_AM29LV800B	0x225B
#define DID_AM29LV400B	0x22BA
#define DID_AM29LV160B	0x2249
#define DID_AM29LV160T	0x22C4
#define DID_AM29LV320T	0x22F6
#define DID_AM29LV320B	0x22F9
#define DID_AM29LV320M	0x227E 
#define DID_MX29LV320T	0x22A7
#define DID_MX29LV320B	0x22A8
#define DID_AT49BV162A	0x00C0		// ATMEL 2MB Boot Block Flash
#define DID_AT49BV322A	0x00C8		// ATMEL 4MB Boot Block Flash
#define DID_SST39VF160	0x2782		// SST	2MB Uniform Flash
#define DID_SST39VF1601	0x234B		// SST	2MB Uniform Flash
#define DID_SST39VF1602	0x234A		// SST	2MB Uniform Flash
#define DID_SST39VF320	0x2783		// SST	4MB Uniform Flash
#define DID_SST39VF3201	0x235B		// SST	4MB Uniform Flash
#define DID_SST39VF3202	0x235A		// SST	4MB Uniform Flash

/***************************************************************/
/*        MESSAGE Control                                      */
/***************************************************************/
#if FLASHDRV_DEBUG
#  ifdef __KERNEL__
#    define PDEBUG(fmt, args...)	printk( fmt, ## args)
#  else
#    define PDEBUG(fmt, args...)	printf( fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...)		do { }while(0)
#endif

#ifdef __KERNEL__
# define PERROR(fmt, args...)		printk( fmt, ## args)
# define PMESSAGE(fmt, args...)		printk( fmt, ## args)
#else
# define PERROR(fmt, args...)		printf( fmt, ## args)
# define PMESSAGE(fmt, args...)		printf( fmt, ## args)
#endif

/*=============================================================*/
/*       Struct definition                                     */
/*=============================================================*/

struct cfiquery
{
	UINT16			cmdset;				// The command set id
	UINT16			boot;				// Boot Sector Flag
	UINT16			psize;				// The size of page memory (Bytes)
	
	UINT32			device_size;			// The total size of this device (Bytes)
	UINT8			block_num;			// The total count of blocks in this device.
	struct
	{
		int sector_num;
		int sector_size;
	} blocks[FLASHDRV_MAX_BLOCK_NUM];			// Block Information.
};

struct blockinfo
{
	int	addr;		// block address
	int	secsz;		// sector size
	int	secnum;		// sector number
};

struct sectorinfo
{
	int	addr;		// sector address
	int	size;		// sector size
};

// Dante : Please refers to page 5 of CFI publication 100
#define CMDSET_UNKNOWN		0x0000			// Command Set Unknown
#define CMDSET_INTEL_STD	0x0003			// Intel Standard Command Set
#define CMDSET_INTEL_EXT	0x0001			// Intel Extended Command Set
#define CMDSET_AMD_STD		0x0002			// AMD Standard Command Set
#define CMDSET_AMD_EXT		0x0004			// AMD Extended Command Set
#define CMDSET_MITSUBISHI_STD	0x0100			// Mitsubishi Standard Command Set
#define CMDSET_MITSUBISHI_EXT	0x0101			// Mitsubishi Standard Command Set
#define CMDSET_SST_STD		0x0701			// SST Standard Command Set

struct command_set
{	
	UINT16	id;		// The id of command set
	
	int	addr1;		// Command Address 1
	int	addr2;		// Command Address 2
	UINT16	unlock1;	// Unlock Command Code 1
	UINT16	unlock2;	// Unlock Command Code 2
	
	UINT16	reset;
	UINT16	write;	
	UINT16	erase_chip;
	UINT16	erase_sector;
	UINT16	suspend;
	UINT16	resume;
			
	int	(*fp_reset)(void);	
	int	(*fp_write_std)(int sector, int offset, const void *data, int numbytes);
	int	(*fp_write_page)(int sector, int offset, const void *data, int numbytes);
	int	(*fp_erase_chip)(void);
	int	(*fp_erase_sector)(int sector);
	int	(*fp_erase_suspend)(void);
	int	(*fp_erase_resume)(void);	
};

struct flashinfo
{	
	struct command_set	*cmdset;
	UINT16			mid;					// Manufactory ID
	UINT16			did;					// Device ID		
	int			size;					// The size of flash device (Bytes)
	int			psize;					// The size of page memory (Bytes)
	int			config;					// The config of the flash	
	
	int			blknum;					// The number of the blocks inside the flash
	struct blockinfo	blocks[8];				// The information of blocks
	
	int			sectornum;				// The number of the sectors inside the flash
	struct sectorinfo	sectors[FLASHDRV_MAX_SECTOR_NUM];	// The information of sectors
};
			
#define FLASH_CONF_BOOTSECTOR		(BIT0 | BIT1)		
#define FLASH_CONF_UNLOCKBYPASS		(BIT2)			// 0 - Not Support, 1 - Support
#define FLASH_CONF_PAGEMODE		(BIT3)			// 0 - Not Support, 1 - Support

#define FLASH_BS_UNKNOWN		0			// Boot Sector - Unknown
#define FLASH_BS_BBOOT			1			// Boot Sector - Bottom Boot
#define FLASH_BS_TBOOT			2			// Boot Sector - Top Boot
#define FLASH_BS_UNIFORM		3			// Boot Sector - Uniform

/*=============================================================*/
/*       Function Declaration                                  */
/*=============================================================*/

int flashdrv_init(struct map_info *map);
int flashdrv_reset(void);

int flashdrv_read(int sector, int offset, void *buffer, int numbytes);
int flashdrv_write(int sector, int offset, const void *data, int numbytes);

int flashdrv_erase_sector(int sector);
int flashdrv_erase_suspend(void);
int flashdrv_erase_resume(void);

int flashdrv_get_blocknum(void);
int flashdrv_get_block_addr(int blk);
int flashdrv_get_block_sectorsz(int blk);
int flashdrv_get_block_sectornum(int blk);

int flashdrv_get_sectornum(void);
int flashdrv_get_sector_addr(int sector);
int flashdrv_get_sector_size(int sector);
int flashdrv_get_size(void);
int flashdrv_get_sector(int addr);

volatile UINT8 *flashdrv_get_memptr(int sector);

#endif
