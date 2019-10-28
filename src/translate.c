/* $Id: translate.c,v 1.4 2005/05/15 20:15:28 harbourn Exp $
 * dcfldd - The Enhanced Forensic DD
 * By Nicholas Harbour
 */

/* Copyright 85, 90, 91, 1995-2001, 2005 Free Software Foundation, Inc.
   Copyright 2012                        Miah Gregory <mace@debian.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* GNU dd originally written by Paul Rubin, David MacKenzie, and Stuart Kemp. */

#include "dcfldd.h"
#include "log.h"
#include "util.h"

/* Output representation of newline and space characters.
   They change if we're converting to EBCDIC.  */
unsigned char newline_character = '\n';
unsigned char space_character = ' ';

/* Translation table formed by applying successive transformations. */
unsigned char trans_table[256];

unsigned char const ascii_to_ebcdic[] =
{
    0, 01, 02, 03, 067, 055, 056, 057,
    026, 05, 045, 013, 014, 015, 016, 017,
    020, 021, 022, 023, 074, 075, 062, 046,
    030, 031, 077, 047, 034, 035, 036, 037,
    0100, 0117, 0177, 0173, 0133, 0154, 0120, 0175,
    0115, 0135, 0134, 0116, 0153, 0140, 0113, 0141,
    0360, 0361, 0362, 0363, 0364, 0365, 0366, 0367,
    0370, 0371, 0172, 0136, 0114, 0176, 0156, 0157,
    0174, 0301, 0302, 0303, 0304, 0305, 0306, 0307,
    0310, 0311, 0321, 0322, 0323, 0324, 0325, 0326,
    0327, 0330, 0331, 0342, 0343, 0344, 0345, 0346,
    0347, 0350, 0351, 0112, 0340, 0132, 0137, 0155,
    0171, 0201, 0202, 0203, 0204, 0205, 0206, 0207,
    0210, 0211, 0221, 0222, 0223, 0224, 0225, 0226,
    0227, 0230, 0231, 0242, 0243, 0244, 0245, 0246,
    0247, 0250, 0251, 0300, 0152, 0320, 0241, 07,
    040, 041, 042, 043, 044, 025, 06, 027,
    050, 051, 052, 053, 054, 011, 012, 033,
    060, 061, 032, 063, 064, 065, 066, 010,
    070, 071, 072, 073, 04, 024, 076, 0341,
    0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110,
    0111, 0121, 0122, 0123, 0124, 0125, 0126, 0127,
    0130, 0131, 0142, 0143, 0144, 0145, 0146, 0147,
    0150, 0151, 0160, 0161, 0162, 0163, 0164, 0165,
    0166, 0167, 0170, 0200, 0212, 0213, 0214, 0215,
    0216, 0217, 0220, 0232, 0233, 0234, 0235, 0236,
    0237, 0240, 0252, 0253, 0254, 0255, 0256, 0257,
    0260, 0261, 0262, 0263, 0264, 0265, 0266, 0267,
    0270, 0271, 0272, 0273, 0274, 0275, 0276, 0277,
    0312, 0313, 0314, 0315, 0316, 0317, 0332, 0333,
    0334, 0335, 0336, 0337, 0352, 0353, 0354, 0355,
    0356, 0357, 0372, 0373, 0374, 0375, 0376, 0377
};

unsigned char const ascii_to_ibm[] =
{
    0, 01, 02, 03, 067, 055, 056, 057,
    026, 05, 045, 013, 014, 015, 016, 017,
    020, 021, 022, 023, 074, 075, 062, 046,
    030, 031, 077, 047, 034, 035, 036, 037,
    0100, 0132, 0177, 0173, 0133, 0154, 0120, 0175,
    0115, 0135, 0134, 0116, 0153, 0140, 0113, 0141,
    0360, 0361, 0362, 0363, 0364, 0365, 0366, 0367,
    0370, 0371, 0172, 0136, 0114, 0176, 0156, 0157,
    0174, 0301, 0302, 0303, 0304, 0305, 0306, 0307,
    0310, 0311, 0321, 0322, 0323, 0324, 0325, 0326,
    0327, 0330, 0331, 0342, 0343, 0344, 0345, 0346,
    0347, 0350, 0351, 0255, 0340, 0275, 0137, 0155,
    0171, 0201, 0202, 0203, 0204, 0205, 0206, 0207,
    0210, 0211, 0221, 0222, 0223, 0224, 0225, 0226,
    0227, 0230, 0231, 0242, 0243, 0244, 0245, 0246,
    0247, 0250, 0251, 0300, 0117, 0320, 0241, 07,
    040, 041, 042, 043, 044, 025, 06, 027,
    050, 051, 052, 053, 054, 011, 012, 033,
    060, 061, 032, 063, 064, 065, 066, 010,
    070, 071, 072, 073, 04, 024, 076, 0341,
    0101, 0102, 0103, 0104, 0105, 0106, 0107, 0110,
    0111, 0121, 0122, 0123, 0124, 0125, 0126, 0127,
    0130, 0131, 0142, 0143, 0144, 0145, 0146, 0147,
    0150, 0151, 0160, 0161, 0162, 0163, 0164, 0165,
    0166, 0167, 0170, 0200, 0212, 0213, 0214, 0215,
    0216, 0217, 0220, 0232, 0233, 0234, 0235, 0236,
    0237, 0240, 0252, 0253, 0254, 0255, 0256, 0257,
    0260, 0261, 0262, 0263, 0264, 0265, 0266, 0267,
    0270, 0271, 0272, 0273, 0274, 0275, 0276, 0277,
    0312, 0313, 0314, 0315, 0316, 0317, 0332, 0333,
    0334, 0335, 0336, 0337, 0352, 0353, 0354, 0355,
    0356, 0357, 0372, 0373, 0374, 0375, 0376, 0377
};

unsigned char const ebcdic_to_ascii[] =
{
    0, 01, 02, 03, 0234, 011, 0206, 0177,
    0227, 0215, 0216, 013, 014, 015, 016, 017,
    020, 021, 022, 023, 0235, 0205, 010, 0207,
    030, 031, 0222, 0217, 034, 035, 036, 037,
    0200, 0201, 0202, 0203, 0204, 012, 027, 033,
    0210, 0211, 0212, 0213, 0214, 05, 06, 07,
    0220, 0221, 026, 0223, 0224, 0225, 0226, 04,
    0230, 0231, 0232, 0233, 024, 025, 0236, 032,
    040, 0240, 0241, 0242, 0243, 0244, 0245, 0246,
    0247, 0250, 0133, 056, 074, 050, 053, 041,
    046, 0251, 0252, 0253, 0254, 0255, 0256, 0257,
    0260, 0261, 0135, 044, 052, 051, 073, 0136,
    055, 057, 0262, 0263, 0264, 0265, 0266, 0267,
    0270, 0271, 0174, 054, 045, 0137, 076, 077,
    0272, 0273, 0274, 0275, 0276, 0277, 0300, 0301,
    0302, 0140, 072, 043, 0100, 047, 075, 042,
    0303, 0141, 0142, 0143, 0144, 0145, 0146, 0147,
    0150, 0151, 0304, 0305, 0306, 0307, 0310, 0311,
    0312, 0152, 0153, 0154, 0155, 0156, 0157, 0160,
    0161, 0162, 0313, 0314, 0315, 0316, 0317, 0320,
    0321, 0176, 0163, 0164, 0165, 0166, 0167, 0170,
    0171, 0172, 0322, 0323, 0324, 0325, 0326, 0327,
    0330, 0331, 0332, 0333, 0334, 0335, 0336, 0337,
    0340, 0341, 0342, 0343, 0344, 0345, 0346, 0347,
    0173, 0101, 0102, 0103, 0104, 0105, 0106, 0107,
    0110, 0111, 0350, 0351, 0352, 0353, 0354, 0355,
    0175, 0112, 0113, 0114, 0115, 0116, 0117, 0120,
    0121, 0122, 0356, 0357, 0360, 0361, 0362, 0363,
    0134, 0237, 0123, 0124, 0125, 0126, 0127, 0130,
    0131, 0132, 0364, 0365, 0366, 0367, 0370, 0371,
    060, 061, 062, 063, 064, 065, 066, 067,
    070, 071, 0372, 0373, 0374, 0375, 0376, 0377
};


static void translate_charset(const unsigned char *new_trans)
{
    unsigned int i;

    for (i = 0; i < 256; i++)
        trans_table[i] = new_trans[trans_table[i]];
    translation_needed = 1;
}

/* Fix up translation table. */

void apply_translations(void)
{
    unsigned int i;

#define MX(a) (bit_count (conversions_mask & (a)))
    if ((MX (C_ASCII | C_EBCDIC | C_IBM) > 1)
        || (MX (C_BLOCK | C_UNBLOCK) > 1)
        || (MX (C_LCASE | C_UCASE) > 1)
        || (MX (C_UNBLOCK | C_SYNC) > 1))
    {
        log_info("\
only one conv in {ascii,ebcdic,ibm}, {lcase,ucase}, {block,unblock}, {unblock,sync}");
    }
#undef MX

    if (conversions_mask & C_ASCII)
        translate_charset(ebcdic_to_ascii);

    if (conversions_mask & C_UCASE) {
        for (i = 0; i < 256; i++)
            if (ISLOWER(trans_table[i]))
                trans_table[i] = TOUPPER(trans_table[i]);
        translation_needed = 1;
    } else if (conversions_mask & C_LCASE) {
        for (i = 0; i < 256; i++)
            if (ISUPPER(trans_table[i]))
                trans_table[i] = TOLOWER(trans_table[i]);
        translation_needed = 1;
    }

    if (conversions_mask & C_EBCDIC) {
        translate_charset (ascii_to_ebcdic);
        newline_character = ascii_to_ebcdic['\n'];
        space_character = ascii_to_ebcdic[' '];
    } else if (conversions_mask & C_IBM) {
        translate_charset (ascii_to_ibm);
        newline_character = ascii_to_ibm['\n'];
        space_character = ascii_to_ibm[' '];
    }
}

/* Apply the character-set translations specified by the user
   to the NREAD bytes in BUF.  */

void translate_buffer(unsigned char *buf, size_t nread)
{
    unsigned char *cp;
    size_t i;

    for (i = nread, cp = buf; i; i--, cp++)
        *cp = trans_table[*cp];
}
