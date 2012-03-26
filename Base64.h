/* Copyright (C) 2008, 2009 Inge Eivind Henriksen
	 See the file COPYING that comes with this distribution for copying permission.
	 */
/*! \file
 * \brief Contains the CBase64 class headers
 */
#include <cstdlib>
#include <iostream>


#pragma once

class CBase64 {
	private:
		static const char encodeCharacterTable[];
		static const char decodeCharacterTable[];
	public:
		CBase64();
		~CBase64();
		void Encode(std::istream &in, std::stringstream &out);
		void Decode(std::istringstream &in, std::stringstream &out);
};
