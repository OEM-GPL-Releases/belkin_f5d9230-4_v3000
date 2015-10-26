/***************************************************************/
/* Dante Su  2004.05.21                                        */
/***************************************************************/
#ifndef _CMDSET_INTEL_H
#define _CMDSET_INTEL_H

int cmdset_intel_reset(void);
int cmdset_intel_write_std(int sector, int offset, const void *data, int numbytes);
int cmdset_intel_erase_sector(int sector);

#endif
