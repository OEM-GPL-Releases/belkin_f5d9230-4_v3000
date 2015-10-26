/***************************************************************/
/* Dante Su  2004.05.21                                        */
/***************************************************************/
#ifndef _CMDSET_AMD_H
#define _CMDSET_AMD_H

int cmdset_amd_reset(void);
int cmdset_amd_unlock_bypass(void);
int cmdset_amd_unlock_bypass_reset(void);
int cmdset_amd_write_std(int sector, int offset, const void *data, int numbytes);
int cmdset_amd_write_page(int sector, int offset, const void *data, int numbytes);
int cmdset_amd_erase_chip(void);
int cmdset_amd_erase_sector(int sector);
int cmdset_amd_erase_suspend(void);
int cmdset_amd_erase_resume(void);

#endif
