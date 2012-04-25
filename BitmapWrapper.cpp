#include "BitmapWrapper.h"
#include <cstring>
#include <cmath>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>


using namespace std;


/**
 * Wrap BMP data around an image, given as a binary vector
 *
 **/
vector<unsigned char> encodeImage(vector<unsigned char> data) {
	unsigned int payload = (int) data.size() - 1;
	unsigned int width = static_cast<int>(ceil(sqrt(static_cast<double>(payload) / 3)));
	unsigned int height = static_cast<int>(ceil((static_cast<double>(payload) / width) / 3));
	unsigned int linepadding = 4 - ((width*3) % 4); // row length must be divisible by 4; calculate padding


	unsigned int filesize = 
		width*height*3  // BMP raw RGB data
		+ height*linepadding // Padding per line
		+ _BMPHEADERSIZE // BMP Header
		;


	// Embedded total size
	unsigned int embedded_size = filesize - _BMPHEADERSIZE;
	// Padding to append behind payload
	unsigned int payload_padding = (width * height * 3) - payload;

	// Create new header with the computed data

	unsigned char header[_BMPHEADERSIZE];
	memcpy(header,_BMPHEADER_,_BMPHEADERSIZE);

	cout << "Payload: " << payload << endl;
	cout << "width: " << width << endl;
	cout << "height: " << height << endl;
	cout << "linepadding: " << linepadding << endl;
	cout << "Embedded total size : " << embedded_size << endl;
	cout << "filesize : " << filesize << endl;
	cout << "payload_padding: " << payload_padding << endl;


	// Override necessary parts
	writeint(header, _BMPOFFSET_SIZE, filesize);
	writeint(header, _BMPOFFSET_WIDTH, width);
	writeint(header, _BMPOFFSET_HEIGHT, height);
	writeint(header, _BMPOFFSET_EMBEDDED_SIZE, embedded_size);
	writeint(header, _BMPOFFSET_PAYLOAD, payload);

	// Initialize bmp vector with header
	vector<unsigned char> bmp;
	for (size_t i = 0; i < _BMPHEADERSIZE; i++) {
		bmp.push_back(header[i]);
	}

	unsigned int rowlen = width * 3;
	unsigned int pos = 0;	

	while (pos < payload) {
		// Data line
		for (size_t i = 0; i < rowlen; i++) {
			if (pos > payload)
				break;

			bmp.push_back(data[pos]);
			pos++;
		}
		// Line padding
		for (size_t n = 0; n < linepadding; n++) {
			bmp.push_back(0);
		}
	}
	// Add payload padding
	for (size_t i = 0; i < payload_padding; i++) {
		bmp.push_back(0);
	}

//	cout << "Wrapped:" << endl;
//	for (size_t i = 0; i < bmp.size(); i++) {
//		cout << hex << setfill('0') << setw(2) << (int) bmp[i];
//	}
//    
//    cout << "****" << endl;
//

    
	return bmp;
}

/**
 * Decode a BMP and return its payload
 *
 **/
vector<unsigned char> decodeImage(vector<unsigned char> data) {
	vector<unsigned char>::iterator it;
	it = data.begin();
    
    
    cout << endl << "***" << endl;
    for (int i = 0; i < data.size(); ++i) {
        cout << data[i];
    }
    
    cout << endl;


	unsigned char buf[4];

	// Get bmp width
	copy(it + _BMPOFFSET_WIDTH, it + _BMPOFFSET_WIDTH + 4, buf);
	unsigned int width = parseint(buf);
	// Get bmp height
	copy(it + _BMPOFFSET_HEIGHT, it + _BMPOFFSET_HEIGHT + 4, buf);
	unsigned int height = parseint(buf);
	// Get payload size
	copy(it + _BMPOFFSET_PAYLOAD, it + _BMPOFFSET_PAYLOAD + 4, buf);
	unsigned int payload = parseint(buf);

	// Calculate linepadding
	unsigned int linepadding = 4 - ((width*3) % 4);

	vector<unsigned char> out;
	unsigned int rowlen = width * 3;
	unsigned int pos = _BMPHEADERSIZE;
	unsigned int toread = payload;
	for (size_t line = 0; line < height; ++line) {
		if (toread >= rowlen) {
			for (size_t col = 0; col < rowlen; ++col) {
				out.push_back(data[pos]);
				pos++;
				toread--;
			}
			// ignore linepadding at the end of each line
			pos += linepadding;
		} else {
			for (size_t lastcol = 0; lastcol <= toread; ++lastcol) {
				out.push_back(data[pos]);
				pos++;
			}
		}
	}
	string t(out.begin(), out.end());
	cout << "width: " << width << endl;
	cout << "height: " << height << endl;
	cout << "linepadding: " << linepadding << endl;
	cout << "Embedded total size : " << payload << " -> " << out.size() << endl;
	cout << "filesize : " << data.size() << endl;

//	cout << "Wrapped:" << endl;
//	for (size_t i = 0; i < data.size(); ++i) {
//		cout << data[i];
//	}
//
//	cout << endl;
//
//	cout << "Unwrapped:" << endl;
//	cout << t << endl;
	return out;

}


int parseint(const unsigned char* bytes) {
	return ((bytes[3] & 0xff) << 24) | ((bytes[2] & 0xff) << 16) | ((bytes[1] & 0xff) << 8) | (bytes[0] & 0xff);
}
void writeint(unsigned char* bytes, int offset, unsigned int value) {
	bytes[offset] =   (value >> 0);
	bytes[offset+1] = (value >> 8);
	bytes[offset+2] = (value >> 16);
	bytes[offset+3] = (value >> 24);
}
