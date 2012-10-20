/**
 * @file   BitmapWrapper.h
 * @author Oliver Guenther (mail@oliverguenther.de)
 * @date   September 2012
 * @brief  Implements Bitmap Wrapping scheme
 *
 * Provides methods for the Wrapping of arbitrary
 * payload into (Windows).
 *
 * Ported from Syncany,
 * http://bazaar.launchpad.net/~syncany-team/syncany
 */

#ifndef __BITMAPWRAPPER__
#define  __BITMAPWRAPPER__

#include <stdint.h>
#include <vector>

/** BMP Header Size */
#define _BMPHEADERSIZE 54

/** BMP Header Offset to Size in Bytes */
#define _BMPOFFSET_SIZE 2

/** BMP Header Offset to embedded Image width */
#define _BMPOFFSET_WIDTH 18

/** BMP Header Offset to embedded Image height */
#define _BMPOFFSET_HEIGHT 22

/** BMP Header Offset to embedded Image size (including BMP line padding) */
#define _BMPOFFSET_EMBEDDED_SIZE 34

/** BMP Header Offset to embedded Image payload length */
#define _BMPOFFSET_PAYLOAD 38

// 	Constant BMP Header to wrap around image data

const unsigned char _BMPHEADER_[] = {
    /* 00 */ 0x42, 0x4d,             // Bitmap Signature
    /* 02 */ 0x00, 0x00, 0x00, 0x00, // size in bytes, filled dynamically
    /* 06 */ 0x00, 0x00,             // reserved, must be zero
    /* 08 */ 0x00, 0x00,             // reserved, must be zero
    /* 10 */ 0x36, 0x00, 0x00, 0x00, // offset to start of image data in bytes
    /* 14 */ 0x28, 0x00, 0x00, 0x00, // size of BITMAPINFOHEADER structure, must be 40 (0x28)
    /* 18 */ 0x00, 0x00, 0x00, 0x00, // image width in pixels, filled dynamically
    /* 22 */ 0x00, 0x00, 0x00, 0x00, // image height in pixels, filled dynamically
    /* 26 */ 0x01, 0x00,             // number of planes, must be 1
    /* 28 */ 0x18, 0x00,             // Bits per Pixel (24)
    /* 30 */ 0x00, 0x00, 0x00, 0x00, // compression type (0=none, 1=RLE-8, 2=RLE-4)
    /* 34 */ 0x00, 0x00, 0x00, 0x00, // size of image data in bytes (including padding)
    /* 38 */ 0x00, 0x00, 0x00, 0x00, // The embedded image's payload length
    /* 42 */ 0x00, 0x00, 0x00, 0x00, // vertical resolution in pixels per meter (unreliable)
    /* 46 */ 0x00, 0x00, 0x00, 0x00, // number of colors in image, or zero
    /* 50 */ 0x00, 0x00, 0x00, 0x00, // number of important colors, or zero
};

/**
 * @brief Encode payload as BMP image
 * @param data A std::vector with binary payload
 * @return The binary payload encoded as a Windows bitmap
 */
std::vector<unsigned char> encodeImage(std::vector<unsigned char> data);
/**
 * @brief Decode a BMP image vector, extracting its payload
 * @param data A std::vector containing a BMP file
 * @return The binary payload
 */
std::vector<unsigned char> decodeImage(std::vector<unsigned char> data);

int parseint(const unsigned char* bytes);
void writeint(unsigned char* bytes, int offset, unsigned int value);

#endif
