#pragma once

// Default number of uint8_ts to allocate in the backing buffer if no size is provided
#define BB_DEFAULT_SIZE 4096

// If defined, utility functions within the class are enabled
#define BB_UTILITY

#include <cstdlib>
#include <cstdint>
#include <cstring>

#include <vector>
#include <memory>

#ifdef BB_UTILITY
#include <iostream>
#include <cstdio>
#endif

class BBuf {
public:
	BBuf(uint32_t size = BB_DEFAULT_SIZE);
	BBuf(const void* arr, uint32_t size);
	~BBuf() = default;

	uint32_t bytes_remaining(); // Number of uint8_ts from the current read position till the end of the buffer
	void clear(); // Clear our the vector and reset read and write positions
	std::unique_ptr<BBuf> clone(); // Return a new instance of a BBuf with the exact same contents and the same state (rpos, wpos)
	//BBuf compact(); // TODO?
	bool equals(const BBuf& other) const; // Compare if the contents are equivalent
	bool operator==(const BBuf& other) const;

	void resize(uint32_t newSize);
	uint32_t size() const; // Size of internal vector

	// Basic Searching (Linear)
	template<typename T> int32_t find(T key, uint32_t start = 0) {
		int32_t ret = -1;
		uint32_t len = buf.size();
		for (uint32_t i = start; i < len; i++) {
			T data = read<T>(i);
			// Wasn't actually found, bounds of buffer were exceeded
			if ((key != 0) && (data == 0))
				break;

			// Key was found in array
			if (data == key) {
				ret = (int32_t) i;
				break;
			}
		}
		return ret;
	}

	// Replacement
	void replace(uint8_t key, uint8_t rep, uint32_t start = 0, bool firstOccuranceOnly = false);

	// Read/Write
	template<typename T> T read() const {
		T data = read<T>(rpos);
		rpos += sizeof(T);
		return data;
	}

	template<typename T> T read(uint32_t index) const {
		if (index + sizeof(T) <= buf.size())
			return *((T*)&buf[index]);
		/*return 0;*/
	}

	template<typename T> void append(T data) {
		uint32_t s = sizeof(data);

		if (size() < (wpos + s))
			buf.resize(wpos + s);
		memcpy(&buf[wpos], (uint8_t*)&data, s);
		//printf("writing %c to %i\n", (uint8_t)data, wpos);

		wpos += s;
	}

	template<typename T> void insert(T data, uint32_t index) {
		if ((index + sizeof(data)) > size())
			return;

		memcpy(&buf[index], (uint8_t*)&data, sizeof(data));
		wpos = index + sizeof(data);
	}

	// Read

	uint8_t peek() const; // Relative peek. Reads and returns the next uint8_t in the buffer from the current position but does not increment the read position
	uint8_t get() const; // Relative get method. Reads the uint8_t at the buffers current position then increments the position
	uint8_t get(uint32_t index) const; // Absolute get method. Read uint8_t at index
	void get_bytes(uint8_t* buf, uint32_t len) const; // Absolute read into array buf of length len
	char get_char() const; // Relative
	char get_char(uint32_t index) const; // Absolute
	double get_double() const;
	double get_double(uint32_t index) const;
	float get_float() const;
	float get_float(uint32_t index) const;
	uint32_t get_int() const;
	uint32_t get_int(uint32_t index) const;
	uint64_t get_long() const;
	uint64_t get_long(uint32_t index) const;
	uint16_t get_short() const;
	uint16_t get_short(uint32_t index) const;

	// Write

	void put(BBuf* src); // Relative write of the entire contents of another BBuf (src)
	void put(uint8_t b); // Relative write
	void put(uint8_t b, uint32_t index); // Absolute write at index
	void put_bytes(const uint8_t* b, uint32_t len); // Relative write
	void put_bytes(const uint8_t* b, uint32_t len, uint32_t index); // Absolute write starting at index
	void put_char(char value); // Relative
	void put_char(char value, uint32_t index); // Absolute
	void put_double(double value);
	void put_double(double value, uint32_t index);
	void put_float(float value);
	void put_float(float value, uint32_t index);
	void put_int(uint32_t value);
	void put_int(uint32_t value, uint32_t index);
	void put_long(uint64_t value);
	void put_long(uint64_t value, uint32_t index);
	void put_short(uint16_t value);
	void put_short(uint16_t value, uint32_t index);

	// Buffer Position Accessors & Mutators

	void set_rpos(uint32_t r) {
		rpos = r;
	}

	uint32_t get_rpos() const {
		return rpos;
	}

	void set_wpos(uint32_t w) {
		wpos = w;
	}

	uint32_t get_wpos() const {
		return wpos;
	}

	void* data() {
		return buf.data();
	}

	// Utility Functions
#ifdef BB_UTILITY
	void set_name(std::string n);
	std::string get_name();
	void info();
	void print_ah();
	void print_ascii();
	void print_hex();
	void print_pos();
#endif

private:
	uint32_t wpos;
	mutable uint32_t rpos;
public:
	std::vector<uint8_t> buf;

#ifdef BB_UTILITY
	std::string name;
#endif
};

