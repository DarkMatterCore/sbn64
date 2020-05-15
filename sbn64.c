#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#if defined(__MINGW32__) || defined(_MSC_VER)
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

//#define DEBUG

#define VERSION "1.74"

#define EEPROM                  0x200       // 512 bytes (EEPROM 4 Kbits) (used in physical cartridges)
#define EEPROMx4                0x800       // 2 KiB (EEPROM 16 Kbits) (used in physical cartridges) (used in Project64 and Wii64/Not64)
#define EEPROMx8                0x1000      // 4 KiB (EEPROM 32 Kbits) (used in Sixtyforce)
#define EEPROMx32               0x4000      // 16 KiB (EEPROM 128 Kbits) (used in Wii N64 Virtual Console)
#define SRAM                    0x8000      // 32 KiB (SRAM 256 Kbits) (used in physical cartridges) (used in all emulators)
#define FlashRAM                0x20000     // 128 KiB (FlashRAM 1024 Kbits) (used in physical cartridges) (used in all emulators)
#define CtrlPak                 0x8000      // 32 KiB (SRAM 256 Kbits) (used in physical Controller Paks) (used in Sixtyforce)
#define CtrlPakx4               0x20000     // 128 KiB (SRAM 1024 Kbits) (used in Wii64/Not64)
#define CtrlPakx8               0x40000     // 256 KiB (SRAM 2048 Kbits) (used in Project64)

#define CHK_ARG(x)              (strlen(argv[i]) == strlen((x)) && !strncmp((x), argv[i], strlen((x))))

#define SIXTYFORCE_MAGIC1       "60cs"
#define SIXTYFORCE_MAGIC2       "save"
#define SIXTYFORCE_MAGIC3       "head"
#define SIXTYFORCE_MAGIC4       "time"
#define SIXTYFORCE_MAGIC5       "type"
#define SIXTYFORCE_MAGIC6       "size"
#define SIXTYFORCE_MAGIC7       "data"
#define SIXTYFORCE_UNKNOWN      (uint32_t)0x04

#define SIXTYFORCE_EEPROM       0x01
#define SIXTYFORCE_SRAM         0x03
#define SIXTYFORCE_FLASHRAM     0x04
#define SIXTYFORCE_SAVE_TYPE(x) ((x) == SAVE_TYPE_EEPROM ? SIXTYFORCE_EEPROM : ((x) == SAVE_TYPE_SRAM ? SIXTYFORCE_SRAM : SIXTYFORCE_FLASHRAM))

#define SIXTYFORCE_PAK0_MAGIC   0x70616B30  // "pak0" (Big Endian)
#define SIXTYFORCE_PAK0_SIZE    8

#define VALID_SAVE_TYPE(x)      ((x) > SAVE_TYPE_NONE && (x) < SAVE_TYPE_CNT)
#define SAVE_TYPE_STR(x)        (VALID_SAVE_TYPE((x)) ? ((x) == SAVE_TYPE_EEPROM ? "EEPROM" : ((x) == SAVE_TYPE_SRAM ? "SRAM" : ((x) == SAVE_TYPE_FLASHRAM ? "Flash RAM" : "Controller Pak"))) : "Unknown / Invalid")

#define VALID_FORMAT_TYPE(x)    ((x) > FORMAT_TYPE_NONE && (x) < FORMAT_TYPE_CNT)

#define MAX_ELEMENTS(x)         ((sizeof((x))) / (sizeof((x)[0])))
#define MAX_CHARACTERS(x)       (MAX_ELEMENTS((x)) - 1)

#define be_u32(x)               (big_endian_flag ? (x) : __builtin_bswap32((x)))

#define PACKED                  __attribute__((packed))

typedef enum {
    SAVE_TYPE_NONE = 0,
    SAVE_TYPE_EEPROM,
    SAVE_TYPE_SRAM,
    SAVE_TYPE_FLASHRAM,
    SAVE_TYPE_CTRLPAK,
    SAVE_TYPE_CNT
} save_type_t;

typedef enum {
    FORMAT_TYPE_NONE = 0,
    FORMAT_TYPE_WII64,
    FORMAT_TYPE_PROJECT64,
    FORMAT_TYPE_WIIVC,
    FORMAT_TYPE_SIXTYFORCE,
    FORMAT_TYPE_CNT
} format_type_value_t;

typedef struct _format_type_t
{
    char name[0x10];
    format_type_value_t val;
} format_type_t;

typedef struct _sixtyforce_savedata_header_t
{
    char magic1[4];         // "60cs"
    uint32_t filesize;      // Everything after this block
    char magic2[4];         // "head"
    uint8_t rom_header[68]; // First 68 bytes from the ROM image
    char magic3[4];         // "time"
    uint32_t unk1;          // Unknown, seems to always be 0x00000004
    uint32_t time;          // time_t counter
    char magic4[4];         // "save"
    uint32_t savesize;       // Everything after this block
    char magic5[4];         // "type"
    uint32_t unk2;          // Unknown, seems to always be 0x00000004
    uint32_t type;          // Not very clear yet, but it seems that 0x00000001 = EEPROM, 0x00000003 = SRAM and 0x00000004 = FlashRAM. We need more information
    char magic6[4];         // "size"
    uint32_t unk3;          // Unknown, seems to always be 0x00000004
    uint32_t datasize1;     // "data" block size. datasize1 = datasize2
    char magic7[4];         // "data"
    uint32_t datasize2;     // "data" block size. datasize2 = datasize1
} PACKED sixtyforce_savedata_header_t;

static const format_type_t formats[FORMAT_TYPE_CNT] = {
    { "wii64", FORMAT_TYPE_WII64 },
    { "pj64", FORMAT_TYPE_PROJECT64 },
    { "wiivc", FORMAT_TYPE_WIIVC },
    { "sixtyforce", FORMAT_TYPE_SIXTYFORCE }
};

static bool big_endian_flag = false;

/* Function created by paxdiablo @ http://stackoverflow.com/a/4023921 */
static int get_line(char *prmpt, char *buff, size_t sz)
{
    if (!buff || !sz) return -1;
    
    // Get line with buffer overrun protection.
    if (prmpt && strlen(prmpt))
    {
        printf("%s", prmpt);
        fflush(stdout);
    }
    
    if (fgets(buff, sz, stdin) == NULL) return -1;
    
    // If it was too long, there'll be no newline.
    // In that case, we flush to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff) - 1] != '\n')
    {
        int ch = 0, extra = 0;
        while(((ch = getchar()) != '\n') && (ch != EOF)) extra = 1;
        return ((extra == 1) ? -2 : 0);
    }
    
    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff) - 1] = '\0';
    return 0;
}

bool is_big_endian(void)
{
    union {
        uint32_t i;
        uint8_t c[4];
    } test_var = { 0x01020304 };
    
    return (test_var.c[0] == 0x01);
}

static void write_data(FILE *input, FILE *output, size_t size, bool byteswap)
{
    if (!input || !output || !size || (size % 4) != 0) return;
    
    size_t i;
    uint32_t data = 0;
    
    for(i = 0; i < size; i += 4)
    {
        fread(&data, 1, sizeof(uint32_t), input);
        if (byteswap) data = __builtin_bswap32(data);
        fwrite(&data, 1, sizeof(uint32_t), output);
    }
}

static void pad_data(FILE *output, size_t size, bool is_vc)
{
    if (!output || !size) return;
    
    size_t i;
    char nullch = (!is_vc ? 0x00 : 0xAA);
    
    for(i = 0; i < size; i++) fwrite(&nullch, 1, sizeof(char), output);
}

static void usage(char **argv)
{
    if (!argv || !argv[0] || !strlen(argv[0])) return;
    
    printf("\n\tUsage: %s -i [infile] -o [outfile] -s [src_fmt] -d [dst_fmt]\n\n", argv[0]);
    printf("\t\t- infile: Name of the input save file.\n");
    printf("\t\t- outfile: Name of the output save file.\n");
    printf("\t\t- src_fmt: Input save file format.\n");
    printf("\t\t- dst_fmt: Output save file format.\n\n");
    printf("\tPossible input/output format values:\n\n");
    printf("\t\t- \"wii64\": Wii64/Not64 save format.\n");
    printf("\t\t- \"pj64\": Project64 save format.\n");
    printf("\t\t- \"wiivc\": Wii N64 Virtual Console save format.\n");
    printf("\t\t- \"sixtyforce\": Sixtyforce save format.\n\n");
    printf("\tExample:\n\n");
    printf("\t\t%s -i \"ZELDA MAJORA'S MASK.fla\" -o \"majora_wii.fla\" -s pj64 -d wii64\n\n", argv[0]);
    printf("\tNotes:\n\n");
    printf("\t\t- Conversion from Sixtyforce format requested by Morshu9001.\n");
    printf("\t\t- Conversion to Sixtyforce format requested by Ulises Ribas.\n");
}

#ifdef DEBUG
static void hexdump(void *buf, size_t size)
{
    if (!buf || !size) return;
    
    size_t i, j;
    uint8_t *data = (uint8_t*)buf;
    
    for(i = 0; i < size; i += 8)
    {
        printf("\n\t%08X\t", (uint32_t)i);
        
        size_t len = ((size - i) > 8 ? 8 : (size - i));
        
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

static void print_sixtyforce_savedata_header(sixtyforce_savedata_header_t *header)
{
    if (!header) return;
    
    printf("\n\tSixtyforce header contents:\n");
    printf("\n\t- magic1: \"%s\".", header->magic1);
    printf("\n\t- filesize: 0x%08x (%u bytes).", be_u32(header->filesize), be_u32(header->filesize));
    printf("\n\t- magic2: \"%s\".", header->magic2);
    printf("\n\t- rom_header:\n");
    hexdump(header->rom_header, sizeof(header->rom_header));
    printf("\n\t- magic3: \"%s\".", header->magic3);
    printf("\n\t- unk1: 0x%08x.", be_u32(header->unk1));
    printf("\n\t- time: 0x%08x.", be_u32(header->time));
    printf("\n\t- magic4: \"%s\".", header->magic4);
    printf("\n\t- savesize: 0x%08x (%u bytes).", be_u32(header->savesize), be_u32(header->savesize));
    printf("\n\t- magic5: \"%s\".", header->magic5);
    printf("\n\t- unk2: 0x%08x.", be_u32(header->unk2));
    printf("\n\t- type: 0x%08x.", be_u32(header->type));
    printf("\n\t- magic6: \"%s\".", header->magic6);
    printf("\n\t- unk3: 0x%08x.", be_u32(header->unk3));
    printf("\n\t- datasize1: 0x%08x (%u bytes).", be_u32(header->datasize1), be_u32(header->datasize1));
    printf("\n\t- magic7: \"%s\".", header->magic7);
    printf("\n\t- datasize2: 0x%08x (%u bytes).\n", be_u32(header->datasize2), be_u32(header->datasize2));
}
#endif

int main(int argc, char **argv)
{
    int i, j, ret = 0;
    int input = -1, output = -1, src_fmt = -1, dst_fmt = -1;
    
    FILE *infile = NULL, *outfile = NULL;
    size_t infile_size = 0, save_size = 0, outfile_size = 0;
    bool remove_outfile = true, byteswap = false;
    
    save_type_t save_type = SAVE_TYPE_NONE;
    size_t save_type_size = 0;
    
    bool sixtyforce_ctrlpak_available = false;
    size_t sixtyforce_pak0_data_offset = 0, sixtyforce_pak0_data_size = 0;
    
    sixtyforce_savedata_header_t sixtyforce_savedata_header;
    memset(&sixtyforce_savedata_header, 0, sizeof(sixtyforce_savedata_header_t));
    
    char tmp[256] = {0};
    uint32_t data = 0;
    
    big_endian_flag = is_big_endian();
    
    printf("\n\tSimple Byteswapper for N64 Saves v%s - By DarkMatterCore\n", VERSION);
    
#ifdef DEBUG
    printf("\tDetected CPU architecture: %s Endian.\n", (big_endian_flag ? "Big" : "Little"));
#endif
    
    if (argc == 9)
    {
        for(i = 1; i < argc; i++)
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
                    for(j = 0; j < FORMAT_TYPE_CNT; j++)
                    {
                        if (CHK_ARG(formats[j].name))
                        {
                            /* Get index value for the input file format */
                            src_fmt = formats[j].val;
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
                    for(j = 0; j < FORMAT_TYPE_CNT; j++)
                    {
                        if (CHK_ARG(formats[j].name))
                        {
                            /* Get index value for the destination file format */
                            dst_fmt = formats[j].val;
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
    
    if (input < 0 || output < 0 || !VALID_FORMAT_TYPE(src_fmt) || !VALID_FORMAT_TYPE(dst_fmt))
    {
        usage(argv);
        ret = -1;
        goto out;
    }
    
    if (src_fmt == dst_fmt)
    {
        printf("\n\tDestination file format cannot be the same as the source file format.\n\tProcess aborted.\n");
        ret = -2;
        goto out;
    }
    
    infile = fopen(argv[input], "rb");
    if (!infile)
    {
        printf("\n\tError opening \"%s\" for reading.\n", argv[input]);
        ret = -3;
        goto out;
    }
    
    fseek(infile, 0, SEEK_END);
    infile_size = ftell(infile);
    rewind(infile);
    
    if (!infile_size || infile_size > CtrlPakx8 || (infile_size % 4) != 0)
    {
        printf("\n\tInvalid N64 save file.\n");
        if (!infile_size) printf("\n\tFile size is zero!\n");
        if (infile_size > CtrlPakx8) printf("\n\tFile size is greater than %u KiB!\n", (CtrlPakx8 / 1024));
        if ((infile_size % 4) != 0) printf("\n\tFile size is not a multiple of 4!\n");
        ret = -4;
        goto out;
    }
    
    if (src_fmt == FORMAT_TYPE_SIXTYFORCE && infile_size < sizeof(sixtyforce_savedata_header_t))
    {
        printf("\n\tInput save file is not big enough to store a Sixtyforce save header!\n");
        ret = -5;
        goto out;
    }
    
    outfile = fopen(argv[output], "wb");
    if (!outfile)
    {
        printf("\n\tError opening \"%s\" for writing.\n", argv[output]);
        ret = -6;
        goto out;
    }
    
    if (src_fmt == FORMAT_TYPE_SIXTYFORCE)
    {
        /* Check if this is a Sixtyforce save */
        fread(&sixtyforce_savedata_header, 1, sizeof(sixtyforce_savedata_header_t), infile);
        rewind(infile);
        
        if (!strncmp(sixtyforce_savedata_header.magic1, SIXTYFORCE_MAGIC1, strlen(SIXTYFORCE_MAGIC1)) && !strncmp(sixtyforce_savedata_header.magic2, SIXTYFORCE_MAGIC2, strlen(SIXTYFORCE_MAGIC2)) && \
            !strncmp(sixtyforce_savedata_header.magic3, SIXTYFORCE_MAGIC3, strlen(SIXTYFORCE_MAGIC3)) && !strncmp(sixtyforce_savedata_header.magic4, SIXTYFORCE_MAGIC4, strlen(SIXTYFORCE_MAGIC4)) && \
            !strncmp(sixtyforce_savedata_header.magic5, SIXTYFORCE_MAGIC5, strlen(SIXTYFORCE_MAGIC5)) && !strncmp(sixtyforce_savedata_header.magic6, SIXTYFORCE_MAGIC6, strlen(SIXTYFORCE_MAGIC6)) && \
            !strncmp(sixtyforce_savedata_header.magic7, SIXTYFORCE_MAGIC7, strlen(SIXTYFORCE_MAGIC7)))
        {
#ifdef DEBUG
            print_sixtyforce_savedata_header(&sixtyforce_savedata_header);
#endif
            
            /* Get save size */
            save_size = be_u32(sixtyforce_savedata_header.datasize2); // Stored in Big Endian
            
            /* Check if this file contains a Controller Pak save */
            sixtyforce_pak0_data_offset = (sizeof(sixtyforce_savedata_header_t) + save_size + SIXTYFORCE_PAK0_SIZE);
            if (infile_size > sixtyforce_pak0_data_offset)
            {
                fseek(infile, sizeof(sixtyforce_savedata_header_t) + save_size, SEEK_SET);
                fread(&data, 1, sizeof(uint32_t), infile);
                rewind(infile);
                
                sixtyforce_ctrlpak_available = (data == be_u32(SIXTYFORCE_PAK0_MAGIC));
                if (sixtyforce_ctrlpak_available) sixtyforce_pak0_data_size = (infile_size - sixtyforce_pak0_data_offset); // Remaining data
            }
            
            /* Prepare file stream position for data access */
            fseek(infile, sizeof(sixtyforce_savedata_header_t), SEEK_SET);
        } else {
            printf("\n\tInput save file is not a Sixtyforce save!\n");
            ret = -7;
            goto out;
        }
    } else {
        /* Get save size */
        save_size = infile_size;
    }
    
    /* Try to guess the most probable save type using the save file size */
    if (save_size <= EEPROM)
    {
        save_type = SAVE_TYPE_EEPROM;
        save_type_size = EEPROM;
    } else
    if (save_size <= EEPROMx4)
    {
        save_type = SAVE_TYPE_EEPROM;
        save_type_size = EEPROMx4;
    } else
    if (save_size <= EEPROMx8)
    {
        save_type = SAVE_TYPE_EEPROM;
        save_type_size = EEPROMx8;
    } else
    if (save_size <= EEPROMx32)
    {
        save_type = SAVE_TYPE_EEPROM;
        save_type_size = EEPROMx32;
    } else
    if (save_size <= SRAM)
    {
        /* Even though this is the real size for Controller Pak saves, only Sixtyforce seems to use it */
        /* Let's just assume it's a SRAM save and call it a day */
        save_type = SAVE_TYPE_SRAM;
        save_type_size = SRAM;
    } else
    if (save_size <= FlashRAM)
    {
        /* Also applies to Controller Pak saves from Wii64/Not64. We'll ask about this later. */
        save_type = SAVE_TYPE_FLASHRAM;
        save_type_size = FlashRAM;
    } else
    if (save_size <= CtrlPakx8)
    {
        save_type = SAVE_TYPE_CTRLPAK;
        save_type_size = CtrlPakx8;
    }
    
    if (src_fmt == FORMAT_TYPE_WII64 && save_type == SAVE_TYPE_FLASHRAM)
    {
        if (!strncasecmp(argv[input] + strlen(argv[input]) - 4, ".fla", 4))
        {
            /* Assume that the input file is actually a FlashRAM save and remain unchanged */
        } else
        if (!strncasecmp(argv[input] + strlen(argv[input]) - 4, ".mpk", 4))
        {
            /* Assume that the input file is actually a Controller Pak save */
            save_type = SAVE_TYPE_CTRLPAK;
        } else {
            /* Ask the user if the input save is actually a Controller Pak save */
            while(true)
            {
                if (get_line("\n\tIs the input file a Controller Pak save? (yes/no): ", tmp, sizeof(tmp)) == 0)
                {
                    if (strlen(tmp) == 3 && !strncmp(tmp, "yes", 3))
                    {
                        /* Change save type */
                        save_type = SAVE_TYPE_CTRLPAK;
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
    
    printf("\n\tDetected save type: %s (%" PRIu64 " Kbits).\n", SAVE_TYPE_STR(save_type), ((save_type_size * 8) / 1024));
    
    if (src_fmt == FORMAT_TYPE_SIXTYFORCE && sixtyforce_ctrlpak_available && (dst_fmt == FORMAT_TYPE_WII64 || dst_fmt == FORMAT_TYPE_PROJECT64))
    {
        printf("\n\tDetected Sixtyforce Controller Pak save data (SRAM %u Kbits).\n", ((CtrlPak * 8) / 1024));
    }
    
    if (dst_fmt == FORMAT_TYPE_WIIVC && save_type == SAVE_TYPE_CTRLPAK)
    {
        printf("\n\tWii N64 Virtual Console isn't compatible with\n\tController Pak save data.\n");
        ret = -8;
        goto out;
    }
    
    if (dst_fmt == FORMAT_TYPE_SIXTYFORCE && save_type == SAVE_TYPE_CTRLPAK)
    {
        printf("\n\tConversion of Controller Pak data to the Sixtyforce format\n\tisn't supported (yet).\n");
        ret = -9;
        goto out;
    }
    
    switch(save_type)
    {
        case SAVE_TYPE_EEPROM:
            /* Byteswapping isn't needed */
            byteswap = false;
            
            /* Adjust output save size according to the destination format */
            outfile_size = ((dst_fmt == FORMAT_TYPE_WII64 || dst_fmt == FORMAT_TYPE_PROJECT64) ? EEPROMx4 : (dst_fmt == FORMAT_TYPE_WIIVC ? EEPROMx32 : EEPROMx8));
            
            break;
        case SAVE_TYPE_SRAM: // SRAM
            /* Only apply 32-bit byteswapping if either the source or destiny format is Project64 */
            byteswap = (src_fmt == FORMAT_TYPE_PROJECT64 || dst_fmt == FORMAT_TYPE_PROJECT64);
            
            /* Adjust output save size */
            outfile_size = SRAM;
            
            break;
        case SAVE_TYPE_FLASHRAM: // Flash RAM
            /* Only apply 32-bit byteswapping if either the source or destiny format is Project64 */
            byteswap = (src_fmt == FORMAT_TYPE_PROJECT64 || dst_fmt == FORMAT_TYPE_PROJECT64);
            
            /* Adjust output save size */
            outfile_size = FlashRAM;
            
            break;
        case SAVE_TYPE_CTRLPAK: // Controller Pak
            /* Byteswapping isn't needed */
            byteswap = false;
            
            /* Adjust output save size according to the destination format */
            outfile_size = (dst_fmt == FORMAT_TYPE_WII64 ? CtrlPakx4 : CtrlPakx8);
            
            break;
        default:
            break;
    }
    
    /* Redundancy checks: */
    /* Wii64/Not64 EEPROM -> Project64 EEPROM */
    /* Project64 EEPROM -> Wii64/Not64 EEPROM */
    /* Wii64/Not64 SRAM -> Wii N64 VC SRAM */
    /* Wii N64 VC SRAM -> Wii64/Not64 SRAM */
    /* Wii64/Not64 FlashRAM -> Wii (U) N64 VC FlashRAM */
    /* Wii (U) N64 VC FlashRAM -> Wii64/Not64 FlashRAM */
    if (save_type_size == outfile_size && ( \
       (save_type == SAVE_TYPE_EEPROM && ((src_fmt == FORMAT_TYPE_WII64 && dst_fmt == FORMAT_TYPE_PROJECT64) || (src_fmt == FORMAT_TYPE_WII64 && dst_fmt == FORMAT_TYPE_PROJECT64))) || \
       (save_type == SAVE_TYPE_SRAM && ((src_fmt == FORMAT_TYPE_WII64 && dst_fmt == FORMAT_TYPE_WIIVC) || (src_fmt == FORMAT_TYPE_WIIVC && dst_fmt == FORMAT_TYPE_WII64))) || \
       (save_type == SAVE_TYPE_FLASHRAM && ((src_fmt == FORMAT_TYPE_WII64 && dst_fmt == FORMAT_TYPE_WIIVC) || (src_fmt == FORMAT_TYPE_WIIVC && dst_fmt == FORMAT_TYPE_WII64))) \
       ))
    {
        printf("\n\tThis %s save file doesn't need to be modified.\n\tJust try it with %s.\n", \
               SAVE_TYPE_STR(save_type), \
               (dst_fmt == FORMAT_TYPE_WII64 ? "Wii64/Not64" : (dst_fmt == FORMAT_TYPE_PROJECT64 ? "Project64" : "your Wii N64 Virtual Console title")));
        ret = -10;
        goto out;
    }
    
    /* Time to do the magic */
    
    if (dst_fmt == FORMAT_TYPE_SIXTYFORCE) // Sixtyforce
    {
        /* Generate Sixtyforce header */
        strcpy(sixtyforce_savedata_header.magic1, SIXTYFORCE_MAGIC1);
        sixtyforce_savedata_header.filesize = be_u32((uint32_t)(sizeof(sixtyforce_savedata_header_t) - 0x08 + outfile_size));
        strcpy(sixtyforce_savedata_header.magic2, SIXTYFORCE_MAGIC2);
        strcpy(sixtyforce_savedata_header.magic3, SIXTYFORCE_MAGIC3);
        sixtyforce_savedata_header.unk1 = be_u32(SIXTYFORCE_UNKNOWN);
        strcpy(sixtyforce_savedata_header.magic4, SIXTYFORCE_MAGIC4);
        sixtyforce_savedata_header.savesize = be_u32((uint32_t)(sizeof(sixtyforce_savedata_header_t) - 0x64 + outfile_size));
        strcpy(sixtyforce_savedata_header.magic5, SIXTYFORCE_MAGIC5);
        sixtyforce_savedata_header.unk2 = be_u32(SIXTYFORCE_UNKNOWN);
        sixtyforce_savedata_header.type = be_u32(SIXTYFORCE_SAVE_TYPE(save_type));
        strcpy(sixtyforce_savedata_header.magic6, SIXTYFORCE_MAGIC6);
        sixtyforce_savedata_header.unk3 = be_u32(SIXTYFORCE_UNKNOWN);
        sixtyforce_savedata_header.datasize1 = be_u32(outfile_size);
        strcpy(sixtyforce_savedata_header.magic7, SIXTYFORCE_MAGIC7);
        sixtyforce_savedata_header.datasize2 = be_u32(outfile_size);
        
#ifdef DEBUG
        print_sixtyforce_savedata_header(&sixtyforce_savedata_header);
#endif
        
        /* Write header to the output file */
        fwrite(&sixtyforce_savedata_header, 1, sizeof(sixtyforce_savedata_header_t), outfile);
    }
    
    /* Write save data */
    write_data(infile, outfile, (outfile_size > save_size ? save_size : outfile_size), byteswap);
    if (outfile_size > save_size) pad_data(outfile, (outfile_size - save_size), (dst_fmt == FORMAT_TYPE_WIIVC));
    remove_outfile = false;
    
    /* Extract the Controller Pak data from the Sixtyforce save (if available) */
    if (sixtyforce_ctrlpak_available && (dst_fmt == FORMAT_TYPE_WII64 || dst_fmt == FORMAT_TYPE_PROJECT64))
    {
        rewind(infile);
        fseek(infile, sixtyforce_pak0_data_offset, SEEK_SET);
        
        /* Generate output filename for the Controller Pak data */
        char *ptr = strrchr(argv[output], '.');
        if (ptr != NULL)
        {
            snprintf(tmp, MAX_CHARACTERS(tmp), "%.*s.mpk", (int)(ptr - argv[output]), argv[output]);
        } else {
            snprintf(tmp, MAX_CHARACTERS(tmp), "%s.mpk", argv[output]);
        }
        
        FILE *cpak = fopen(tmp, "wb");
        if (cpak)
        {
            write_data(infile, cpak, sixtyforce_pak0_data_size, false);
            pad_data(cpak, (dst_fmt == FORMAT_TYPE_WII64 ? (CtrlPakx4 - sixtyforce_pak0_data_size) : (CtrlPakx8 - sixtyforce_pak0_data_size)), false);
            
            fclose(cpak);
            
            printf("\n\tSaved additional Controller Pak data to \"%s\".", tmp);
            printf("\n\tYou can use it with %s.\n", (dst_fmt == FORMAT_TYPE_WII64 ? "Wii64/Not64" : "Project64"));
        } else {
            printf("\n\tError opening \"%s\" for writing.\n", tmp);
        }
    }
    
    printf("\n\tConversion process successfully completed!\n");
    
out:
    if (outfile) fclose(outfile);
    if (output >= 0 && remove_outfile) remove(argv[output]);
    if (infile) fclose(infile);
    
    return ret;
}
