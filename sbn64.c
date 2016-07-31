#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#define VERSION "1.41"

#define EEPROMx4	0x800	// 2 KB
#define SRAM		0x8000	// 32 KB
#define FlashRAM	0x20000	// 128 KB
#define CtrlPak		0x40000	// 256 KB
#define VC_EEP		0x4000	// 16 KB

#define SIXTY_MAGIC 0x64617461 // "data"

#define bswap_32(a) ((((a) << 24) & 0xff000000) | (((a) << 8) & 0xff0000) | (((a) >> 8) & 0xff00) | (((a) >> 24) & 0xff))

void write_data(uint32_t data, FILE *input, FILE *output, uint32_t size, bool byteswap)
{
	int i = 0;
	
	while (i < size)
	{
		fread(&data, 4, 1, input);
		if (byteswap) data = bswap_32(data);
		fwrite(&data, 4, 1, output);
		i += 4;
	}
}	

void pad_data(bool is_vc, uint32_t pad_size, FILE *output)
{
	if (pad_size > 0)
	{
		int i;
		char nullch[1];
		
		nullch[0] = (!is_vc ? 0x00 : 0xAA);
		
		for (i = 0; i < pad_size; i++) fwrite(nullch, 1, 1, output);
	}
}

int main(int argc, char **argv)
{
	if (argc < 3 || argc > 4 || (argc == 4 && strncmp(argv[3], "/vc_save", 8) != 0))
	{
		printf("\n\tSimple Byteswapper for N64 Saves v%s - By DarkMatterCore\n", VERSION);
		printf("\tUsage: %s [infile] [outfile] [/vc_save]\n\n", argv[0]);
		printf("\t- infile: Name of the input save file.\n\n");
		printf("\t- outfile: Name of the output save file.\n\n");
		printf("\t- \"/vc_save\" modifier: Convert the save file to the Virtual Console\n");
		printf("\t                       format instead of the Wii64 format.\n");
		printf("\n\tYou can also use Sixtyforce emulator saves as input files to convert");
		printf("\n\tthem to the Mupen64Plus/Wii64 format (feature requested by Morshu9001).\n");
		printf("\n\tExample: %s \"ZELDA MAJORA'S MASK.fla\" \"majora_wii.fla\"\n", argv[0]);
		return 1;
	}
	
	bool vc_save = (argc == 4 && !strncmp(argv[3], "/vc_save", 8));
	
	FILE *infile = fopen(argv[1], "rb");
	if (!infile)
	{
		printf("\n\tError opening \"%s\" for reading.\n", argv[1]);
		return 1;
	}
	
	fseek(infile, 0, SEEK_END);
	uint32_t fsize = ftell(infile);
	rewind(infile);
	
	if (fsize == 0 || fsize > CtrlPak || (fsize % 4) != 0)
	{
		printf("\n\tInvalid N64 save file.\n");
		fclose(infile);
		return 1;
	}
	
	FILE *outfile = fopen(argv[2], "wb");
	if (!outfile)
	{
		fclose(infile);
		printf("\n\tError opening \"%s\" for writing.\n", argv[2]);
		return 1;
	}
	
	uint32_t data = 0;
	bool del = false, sixty = false, sixty_cp = false;
	
	/* First, check if this a Sixtyforce save */
	
	fseek(infile, 0x7C, SEEK_SET);
	fread(&data, 4, 1, infile);
	
	if (data == bswap_32(SIXTY_MAGIC))
	{
		sixty = true;
		
		/* Try to determine the save type by reading the value @ 0x6F */
		/* Needs more testing */
		
		fseek(infile, -0x14, SEEK_CUR); // 0x6C
		fread(&data, 4, 1, infile);
		
		switch ((data >> 24) & 0xff)
		{
			case 0x00: // ???
			case 0x01:
			case 0x02: // ???
				fsize = EEPROMx4;
				break;
			case 0x03:
				/* It seems Sixtyforce wrongly categorizes this as a SRAM save */
				if (fsize == 0x1008C)
				{
					fsize = EEPROMx4;
					sixty_cp = true;
				} else {
					fsize = SRAM;
				}
				break;
			case 0x04:
				fsize = FlashRAM;
				break;
			default:
				break;
		}
		
		/* Prepare file stream position for data access */
		fseek(infile, 0x14, SEEK_CUR); // 0x84
	} else {
		/* Apparently, this is just a normal save */
		rewind(infile);
	}
	
	if (fsize <= EEPROMx4 || strcmp(argv[1] + strlen(argv[1]) - 4, ".eep") == 0 || strcmp(argv[1] + strlen(argv[1]) - 4, ".EEP") == 0)
	{
		/* Wii64 assumes every EEPROM save is the 4x type */
		/* But VC emulators always set their size to 16 KB */
		/* These are the only type of saves that do not need to be byteswapped (apart from MPK files) */
		
		if (sixty || (!vc_save && fsize < EEPROMx4) || (vc_save && fsize < VC_EEP))
		{
			write_data(data, infile, outfile, fsize, false);
			pad_data(vc_save, (!vc_save ? (EEPROMx4 - fsize) : (VC_EEP - fsize)), outfile);
			
			/* Extract the Controller Pak data from the Sixtyforce save (if available) */
			if (sixty_cp)
			{
				fsize = SRAM; // Controller Paks have a length of 32 KB in Sixtyforce saves
				fseek(infile, 0x7808, SEEK_CUR); // SRAM save length - EEPROMx4 save length + 8-byte header
				
				FILE *cpak = fopen("sixtyforce.mpk", "wb");
				if (!cpak)
				{
					printf("\n\tError opening \"sixtyforce.mpk\" for writing.\n");
				} else {
					write_data(data, infile, cpak, fsize, false);
					pad_data(0, (FlashRAM - fsize), cpak); // 0: Remember, VC titles do not use Controller Paks
					
					fclose(cpak);
					
					printf("\n\tSaved additional Controller Pak data to \"sixtyforce.mpk\".");
					printf("\n\tYou can use it with Wii64.\n");
				}
			}
		} else {
			printf("\n\tThis EEPROM save file doesn't need to be modified. Just try it with %s.", (!vc_save ? "Wii64" : "your VC title"));
			del = true;
		}
	} else
	if (fsize == CtrlPak || strcmp(argv[1] + strlen(argv[1]) - 4, ".mpk") == 0 || strcmp(argv[1] + strlen(argv[1]) - 4, ".MPK") == 0)
	{
		/* Wii64 sets the size of every Controller Pak save to 128 KB */
		/* VC titles don't really use Controller Pak saves, so the output file will be dismissed if vc_save == true */
		
		if (!vc_save)
		{
			if (fsize != FlashRAM)
			{
				write_data(data, infile, outfile, ((fsize < FlashRAM) ? fsize : FlashRAM), false);
				if (fsize < FlashRAM) pad_data(0, (FlashRAM - fsize), outfile);
			} else {
				printf("\n\tThis Controller Pak save file doesn't need to be modified.\n");
				del = true;
			}
		} else {
			printf("\n\tFYI, N64 VC titles do not use Controller Pak saves...\n\tOnly the EEP file needs to be converted.\n");
			printf("\tJust sayin', because you used the \"/vc_save\" modifier.\n");
			del = true;
		}
	} else {
		/* Do the normal 32-bit byteswapping operation (and padding, if needed) */
		/* Only applies to SRAM and Flash RAM saves, though */
		
		write_data(data, infile, outfile, fsize, (sixty ^ 1)); // Byteswapping isn't needed for Sixtyforce saves
		
		if (fsize == SRAM || fsize == FlashRAM)
		{
			printf("\n\tI already converted your savefile, but it didn't need any padding.\n\tTry it.\n");
		} else {
			pad_data(vc_save, ((fsize < SRAM) ? (SRAM - fsize) : (FlashRAM - fsize)), outfile);
		}
	}
	
	fclose(infile);
	fclose(outfile);
	if (del) remove(argv[2]);
	
	return 0;
}
