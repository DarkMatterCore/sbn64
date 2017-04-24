#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#define VERSION "1.51"

#define EEPROM		0x200	// 512 bytes (used in physical cartridges)
#define EEPROMx4	0x800	// 2 KiB (EEPROM 4 Kbits * 4 = 16 Kbits) (used in physical cartridges) (used in Project64 and Wii64)
#define EEPROMx8	0x1000	// 4 KiB (EEPROM 4 Kbits * 8 = 32 Kbits) (used in Sixtyforce)
#define EEPROMx32	0x4000	// 16 KiB (EEPROM 4 Kbits * 32 = 128 Kbits) (used in Wii N64 Virtual Console)
#define SRAM		0x8000	// 32 KiB (SRAM 256 Kbits) (used in physical cartridges) (used in all emulators)
#define FlashRAM	0x20000	// 128 KiB (FlashRAM 1024 Kbits) (used in physical cartridges) (used in all emulators)
#define CtrlPak		0x8000	// 32 KiB (SRAM 256 Kbits) (used in physical Controller Paks) (used in Sixtyforce)
#define CtrlPakx4	0x20000	// 128 KiB (SRAM 256 Kbits * 4 = 1024 Kbits) (used in Wii64)
#define CtrlPakx8	0x40000	// 256 KiB (SRAM 256 Kbits * 8 = 2048 Kbits) (used in Project64)

#define PAK0_MAGIC	0x70616B30 // "pak0" (Big Endian)

#define bswap_32(a)	((((a) << 24) & 0xff000000) | (((a) << 8) & 0xff0000) | (((a) >> 8) & 0xff00) | (((a) >> 24) & 0xff))

#define CHK_ARG(X)	(strlen(argv[i]) == strlen((X)) && !strncmp((X), argv[i], strlen((X))))

const char *formats[] = { "wii64", "pj64", "wiivc", "sixtyforce" };
const int format_cnt = 4;

typedef struct
{
	char magic1[4];			// "60cs"
	uint32_t filesize;		// Everything after this block
	char magic2[4];			// "head"
	uint8_t rom_header[68];	// First 68 bytes from the ROM image
	char magic3[4];			// "time"
	uint32_t unk1;			// Unknown, seems to always be 0x00000004
	uint32_t time;			// time_t counter
	char magic4[4];			// "save"
	uint32_t savesize;		// Everything after this block
	char magic5[4];			// "type"
	uint32_t unk2;			// Unknown, seems to always be 0x00000004
	uint32_t type;			// Not very clear yet, but it seems that 0x00000001 = EEPROM, 0x00000003 = SRAM and 0x00000004 = FlashRAM. We need more information
	char magic6[4];			// "size"
	uint32_t unk3;			// Unknown, seems to always be 0x00000004
	uint32_t datasize1;		// "data" block size. datasize1 = datasize2
	char magic7[4];			// "data"
	uint32_t datasize2;		// "data" block size. datasize2 = datasize1
} sixty_t;

/* Function created by paxdiablo @ http://stackoverflow.com/a/4023921 */
static int getLine (char *prmpt, char *buff, size_t sz)
{
	int ch, extra;
	
	// Get line with buffer overrun protection.
	if (prmpt != NULL)
	{
		printf("%s", prmpt);
		fflush(stdout);
	}
	
	if (fgets(buff, sz, stdin) == NULL) return -1;
	
	// If it was too long, there'll be no newline.
	// In that case, we flush to end of line so that excess doesn't affect the next call.
	if (buff[strlen(buff)-1] != '\n')
	{
		extra = 0;
		while (((ch = getchar()) != '\n') && (ch != EOF)) extra = 1;
		return ((extra == 1) ? -2 : 0);
	}
	
	// Otherwise remove newline and give string back to caller.
	buff[strlen(buff)-1] = '\0';
	return 0;
}

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

void usage(char **argv)
{
	printf("\n\tSimple Byteswapper for N64 Saves v%s - By DarkMatterCore\n", VERSION);
	printf("\tUsage: %s -i [infile] -o [outfile] -s [src_fmt] -d [dst_fmt]\n\n", argv[0]);
	printf("\t- infile: Name of the input save file.\n");
	printf("\t- outfile: Name of the output save file.\n");
	printf("\t- src_fmt: Input save file format.\n");
	printf("\t- dst_fmt: Output save file format.\n\n");
	printf("\tPossible input/output format values:\n\n");
	printf("\t- \"wii64\": Wii64/Mupen64Plus save format.\n");
	printf("\t- \"pj64\": Project64 save format.\n");
	printf("\t- \"wiivc\": Wii N64 Virtual Console save format.\n");
	printf("\t- \"sixtyforce\": Sixtyforce save format.\n\n");
	printf("\tExample:\n\n");
	printf("\t%s -i \"ZELDA MAJORA'S MASK.fla\" -o \"majora_wii.fla\" -s pj64 -d wii64\n\n", argv[0]);
	printf("\tNotes:\n\n");
	printf("\t- Conversion from Sixtyforce format requested by Morshu9001.\n");
	printf("\t- Conversion to Sixtyforce format requested by Ulises Ribas.\n");
}

void hexdump(uint8_t *data, size_t size)
{
	if (!data || !size) return;
	
	int i, j;
	for(i = 0; i < size; i += 8)
	{
		printf("\n\t%08X\t", i);
		
		int len = ((size - i) > 8 ? 8 : (size - i));
		
		for(j = 0; j < len; j++)
		{
			printf("%02X", data[i + j]);
			if (j == (len - 1))
			{
				switch(j)
				{
					case 0:
					case 1:
						printf("\t\t\t\t");
						break;
					case 2:
					case 3:
					case 4:
						printf("\t\t\t");
						break;
					case 5:
					case 6:
					case 7:
						printf("\t\t");
						break;
					default:
						break;
				}
			} else {
				printf(" ");
			}
		}
		
		for(j = 0; j < len; j++) printf("%c", ((data[i + j] >= 0x20 && data[i + j] <= 0x7F) ? (char)data[i + j] : '.'));
	}
	
	printf("\n");
}

void print_sixty_header(sixty_t *header)
{
	if (!header) return;
	
	printf("\n\tSixtyforce header contents:\n");
	printf("\n\t- magic1: \"%s\".", header->magic1);
	printf("\n\t- filesize: 0x%08x (%u bytes).", bswap_32(header->filesize), bswap_32(header->filesize));
	printf("\n\t- magic2: \"%s\".", header->magic2);
	printf("\n\t- rom_header:\n");
	hexdump(header->rom_header, sizeof(header->rom_header));
	printf("\n\t- magic3: \"%s\".", header->magic3);
	printf("\n\t- unk1: 0x%08x.", bswap_32(header->unk1));
	printf("\n\t- time: 0x%08x.", bswap_32(header->time));
	printf("\n\t- magic4: \"%s\".", header->magic4);
	printf("\n\t- savesize: 0x%08x (%u bytes).", bswap_32(header->savesize), bswap_32(header->savesize));
	printf("\n\t- magic5: \"%s\".", header->magic5);
	printf("\n\t- unk2: 0x%08x.", bswap_32(header->unk2));
	printf("\n\t- type: 0x%08x.", bswap_32(header->type));
	printf("\n\t- magic6: \"%s\".", header->magic6);
	printf("\n\t- unk3: 0x%08x.", bswap_32(header->unk3));
	printf("\n\t- datasize1: 0x%08x (%u bytes).", bswap_32(header->datasize1), bswap_32(header->datasize1));
	printf("\n\t- magic7: \"%s\".", header->magic7);
	printf("\n\t- datasize2: 0x%08x (%u bytes).\n", bswap_32(header->datasize2), bswap_32(header->datasize2));
}

int main(int argc, char **argv)
{
	int i, j;
	int input = -1, output = -1, src_fmt = -1, dst_fmt = -1;
	
	if (argc == 9)
	{
		for (i = 1; i < argc; i++)
		{
			if (CHK_ARG("-i"))
			{
				if (input < 0)
				{
					/* Get index value for the input file name */
					i++;
					input = i;
				} else {
					input = -1;
					break;
				}
			} else
			if (CHK_ARG("-o"))
			{
				if (output < 0)
				{
					/* Get index value for the output file name */
					i++;
					output = i;
				} else {
					output = -1;
					break;
				}
			} else
			if (CHK_ARG("-s"))
			{
				if (src_fmt < 0)
				{
					i++;
					
					/* Validate option */
					for (j = 0; j < format_cnt; j++)
					{
						if (CHK_ARG(formats[j]))
						{
							/* Get index value for the input file format */
							src_fmt = j;
							break;
						}
					}
					
					if (src_fmt < 0) break;
				} else {
					src_fmt = -1;
					break;
				}
			} else
			if (CHK_ARG("-d"))
			{
				if (dst_fmt < 0)
				{
					i++;
					
					/* Validate option */
					for (j = 0; j < format_cnt; j++)
					{
						if (CHK_ARG(formats[j]))
						{
							/* Get index value for the input file format */
							dst_fmt = j;
							break;
						}
					}
					
					if (dst_fmt < 0) break;
				} else {
					dst_fmt = -1;
					break;
				}
			}
		}
	}
	
	if (input < 0 || output < 0 || src_fmt < 0 || dst_fmt < 0)
	{
		usage(argv);
		return 1;
	}
	
	if (src_fmt == dst_fmt)
	{
		printf("\n\tDestination file format cannot be the same as the source file format.\n\tProcess aborted.\n");
		return 1;
	}
	
	sixty_t *sixty_header = malloc(sizeof(sixty_t));
	if (!sixty_header)
	{
		printf("\n\tError allocating memory for the save header.\n");
		return 1;
	}
	
	memset(sixty_header, 0, sizeof(sixty_t));
	
	FILE *infile = fopen(argv[input], "rb");
	if (!infile)
	{
		free(sixty_header);
		printf("\n\tError opening \"%s\" for reading.\n", argv[input]);
		return 1;
	}
	
	fseek(infile, 0, SEEK_END);
	uint32_t fsize = ftell(infile);
	rewind(infile);
	
	if (fsize == 0 || fsize > CtrlPakx8 || (fsize % 4) != 0)
	{
		printf("\n\tInvalid N64 save file.\n");
		if (fsize == 0) printf("\n\tFile size is zero!\n");
		if (fsize > CtrlPakx8) printf("\n\tFile size is greater than %u KiB!\n", CtrlPakx8 / 1024);
		if ((fsize % 4) != 0) printf("\n\tFile size is not a multiple of 4!\n");
		fclose(infile);
		return 1;
	}
	
	if (src_fmt == 3 && fsize < sizeof(sixty_t))
	{
		free(sixty_header);
		fclose(infile);
		printf("\n\tInput save file is not big enough to store a Sixtyforce header!\n");
		return 1;
	}
	
	FILE *outfile = fopen(argv[output], "wb");
	if (!outfile)
	{
		free(sixty_header);
		fclose(infile);
		printf("\n\tError opening \"%s\" for writing.\n", argv[output]);
		return 1;
	}
	
	char tmp[256] = {0};
	bool sixty_cp = false;
	uint32_t data = 0, save_size = 0;
	
	if (src_fmt == 3)
	{
		/* Check if this is a Sixtyforce save */
		
		fread(sixty_header, sizeof(sixty_t), 1, infile);
		rewind(infile);
		
		if (!strncmp(sixty_header->magic1, "60cs", 4) && !strncmp(sixty_header->magic2, "head", 4) && !strncmp(sixty_header->magic3, "time", 4) && \
			!strncmp(sixty_header->magic4, "save", 4) && !strncmp(sixty_header->magic5, "type", 4) && !strncmp(sixty_header->magic6, "size", 4) && \
			!strncmp(sixty_header->magic7, "data", 4))
		{
			//print_sixty_header(sixty_header);
			
			/* Get save size */
			save_size = bswap_32(sixty_header->datasize2); // Stored in Big Endian
			
			/* Check if this file contains a Controller Pak save */
			if (fsize > (0x84 + save_size + 8)) // Sixtyforce header + save data + "pak0" block
			{
				fseek(infile, 0x84 + save_size, SEEK_SET);
				fread(&data, 4, 1, infile);
				rewind(infile);
				sixty_cp = (data == bswap_32(PAK0_MAGIC));
			}
			
			/* Prepare file stream position for data access */
			fseek(infile, 0x84, SEEK_SET);
		} else {
			free(sixty_header);
			fclose(infile);
			fclose(outfile);
			remove(argv[output]);
			printf("\n\tInput save file is not a Sixtyforce save!\n");
			return 1;
		}
	} else {
		/* Get save size */
		save_size = fsize;
	}
	
	int type = -1;
	
	switch(save_size)
	{
		case EEPROM:
		case EEPROMx4:
		case EEPROMx8:
		case EEPROMx32:
			type = 0;
			break;
		case SRAM:
			type = 1;
			break;
		case FlashRAM:
			type = 2;
			break;
		case CtrlPakx8:
			type = 3;
			break;
		default:
			break;
	}
	
	if (type == -1)
	{
		free(sixty_header);
		fclose(infile);
		fclose(outfile);
		remove(argv[output]);
		printf("\n\tInvalid N64 save file size.\n\tUnable to determine the save type using the save size.\n");
		return 1;
	}
	
	if (dst_fmt == 2 && type == 3) // Output: Wii N64 VC Controller Pak
	{
		free(sixty_header);
		fclose(infile);
		fclose(outfile);
		remove(argv[output]);
		printf("\n\tWii N64 Virtual Console isn't compatible with\n\tController Pak save data.\n");
		return 1;
	}
	
	if (dst_fmt == 3 && type == 3) // Output: Sixtyforce Controller Pak
	{
		free(sixty_header);
		fclose(infile);
		fclose(outfile);
		remove(argv[output]);
		printf("\n\tConversion of Controller Pak data to the Sixtyforce format\n\tisn't supported (yet).\n");
		return 1;
	}
	
	if (src_fmt == 0 && type == 2) // Input: Wii64 Flash RAM
	{
		if (!strncasecmp(argv[input] + strlen(argv[input]) - 4, ".mpk", 4))
		{
			/* Assume that the input file is actually a Controller Pak save */
			type = 3;
		} else {
			/* Ask the user if the input save is actually a Controller Pak save */
			while(true)
			{
				if (getLine("\n\tIs the input file a Controller Pak save? (yes/no): ", tmp, sizeof(tmp)) == 0)
				{
					if (strlen(tmp) == 3 && !strncmp(tmp, "yes", 3))
					{
						/* Change save type */
						type = 3;
						break;
					} else
					if (strlen(tmp) == 2 && !strncmp(tmp, "no", 2))
					{
						/* Remain unchanged */
						break;
					} else {
						printf("\tInvalid input. Please answer with \"yes\" or \"no\".\n");
					}
				} else {
					printf("\tInvalid input. Please answer with \"yes\" or \"no\".\n");
				}
			}
		}
	}
	
	printf("\n\tDetected save type: %s (%u Kbits).\n", (type == 0 ? "EEPROM" : (type == 1 ? "SRAM" : (type == 2 ? "Flash RAM" : "Controller Pak"))), ((save_size * 8) / 1024));
	if (src_fmt == 3 && sixty_cp && (dst_fmt == 0 || dst_fmt == 1)) printf("\n\tDetected Sixtyforce Controller Pak save data (SRAM %u Kbits).\n", ((CtrlPak * 8) / 1024));
	
	/* Redundancy checks: */
	/* Wii64 EEPROM -> Project64 EEPROM */
	/* Project64 EEPROM -> Wii64 EEPROM */
	/* Wii64 SRAM -> Wii N64 VC SRAM */
	/* Wii N64 VC SRAM -> Wii64 SRAM */
	/* Wii64 FlashRAM -> Wii N64 VC FlashRAM */
	/* Wii N64 VC FlashRAM -> Wii64 FlashRAM */
	if ((((src_fmt == 0 && dst_fmt == 1) || (src_fmt == 1 && dst_fmt == 0)) && type == 0) || \
		(((src_fmt == 0 && dst_fmt == 2) || (src_fmt == 2 && dst_fmt == 0)) && (type == 1 || type == 2)))
	{
		free(sixty_header);
		fclose(infile);
		fclose(outfile);
		remove(argv[output]);
		printf("\n\tThis %s save file doesn't need to be modified.\n\tJust try it with %s.\n", \
			(type == 0 ? "EEPROM" : (type == 1 ? "SRAM" : (type == 2 ? "Flash RAM" : "Controller Pak"))), \
			(dst_fmt == 0 ? "Wii64" : (dst_fmt == 1 ? "Project64" : "your Wii N64 Virtual Console title")));
		return 1;
	}
	
	uint32_t outsize = 0;
	bool byteswap = false;
	
	switch(type)
	{
		case 0: // EEPROM
			/* Byteswapping isn't needed */
			byteswap = false;
			
			/* Adjust output save size according to the destination format */
			outsize = ((dst_fmt == 0 || dst_fmt == 1) ? EEPROMx4 : (dst_fmt == 2 ? EEPROMx32 : EEPROMx8));
			
			break;
		case 1: // SRAM
			/* Only apply 32-bit byteswapping if either the source or destiny format is Project64 */
			byteswap = (src_fmt == 1 || dst_fmt == 1);
			
			/* Adjust output save size */
			outsize = SRAM;
			
			break;
		case 2: // Flash RAM
			/* Only apply 32-bit byteswapping if either the source or destiny format is Project64 */
			byteswap = (src_fmt == 1 || dst_fmt == 1);
			
			/* Adjust output save size */
			outsize = FlashRAM;
			
			break;
		case 3: // Controller Pak
			/* Byteswapping isn't needed */
			byteswap = false;
			
			/* Adjust output save size according to the destination format */
			outsize = (dst_fmt == 0 ? CtrlPakx4 : CtrlPakx8);
			
			break;
		default:
			break;
	}
	
	/* Time to do the magic */
	
	if (dst_fmt == 3) // Sixtyforce
	{
		/* Generate Sixtyforce header */
		strcpy(sixty_header->magic1, "60cs");
		sixty_header->filesize = bswap_32((uint32_t)(0x84 - 0x08 + outsize));
		strcpy(sixty_header->magic2, "head");
		strcpy(sixty_header->magic3, "time");
		sixty_header->unk1 = bswap_32((uint32_t)0x04);
		strcpy(sixty_header->magic4, "save");
		sixty_header->savesize = bswap_32((uint32_t)(0x84 - 0x64 + outsize));
		strcpy(sixty_header->magic5, "type");
		sixty_header->unk2 = bswap_32((uint32_t)0x04);
		sixty_header->type = bswap_32((uint32_t)(type == 0 ? 0x01 : (type == 1 ? 0x03 : 0x04)));
		strcpy(sixty_header->magic6, "size");
		sixty_header->unk3 = bswap_32((uint32_t)0x04);
		sixty_header->datasize1 = bswap_32(outsize);
		strcpy(sixty_header->magic7, "data");
		sixty_header->datasize2 = bswap_32(outsize);
		
		//print_sixty_header(sixty_header);
		
		/* Write header to the output file */
		fwrite(sixty_header, sizeof(sixty_t), 1, outfile);
	}
	
	/* Write save data */
	write_data(data, infile, outfile, (outsize > save_size ? save_size : outsize), byteswap);
	if (outsize > save_size) pad_data((dst_fmt == 2), (outsize - save_size), outfile);
	
	/* Extract the Controller Pak data from the Sixtyforce save (if available) */
	if (sixty_cp && (dst_fmt == 0 || dst_fmt == 1))
	{
		rewind(infile);
		fseek(infile, (0x84 + save_size + 8), SEEK_SET); // Sixtyforce header + save data + "pak0" block
		
		uint32_t pak0_size = (fsize - (0x84 + save_size + 8)); // Remaining data
		
		snprintf(tmp, strlen(argv[output]), argv[output]);
		
		for(i = strlen(tmp); tmp[i] != '.'; i--);
		
		if (i > 0) tmp[i] = '\0';
		strncat(tmp, ".mpk", 4);
		
		FILE *cpak = fopen(tmp, "wb");
		if (!cpak)
		{
			printf("\n\tError opening \"%s\" for writing.\n", tmp);
		} else {
			write_data(data, infile, cpak, pak0_size, false);
			pad_data(false, (dst_fmt == 0 ? (CtrlPakx4 - pak0_size) : (CtrlPakx8 - pak0_size)), cpak);
			
			fclose(cpak);
			
			printf("\n\tSaved additional Controller Pak data to \"%s\".", tmp);
			printf("\n\tYou can use it with %s.\n", (dst_fmt == 0 ? "Wii64" : "Project64"));
		}
	}
	
	printf("\n\tConversion process successfully completed!\n");
	
	free(sixty_header);
	fclose(infile);
	fclose(outfile);
	
	return 0;
}
