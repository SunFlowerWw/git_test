#include "../inc/bbuf.h"
niaho
/**
 * BBuf constructor
 * Reserves specified size in internal vector
 *
 * @param size Size (in bytes) of space to preallocate internally. Default is set in DEFAULT_SIZE
 */
BBuf::BBuf(uint32_t size) {
	buf.reserve(size);
	clear();
#ifdef BB_UTILITY
	name = "";
#endif
}

/**
 * BBuf constructor
 * Consume an entire uint8_t array of length len in the BBuf
 *
 * @param arr uint8_t array of data (should be of length len)
 * @param size Size of space to allocate
 */
BBuf::BBuf(const void* arr, uint32_t size) {
	// If the provided array is NULL, allocate a blank buffer of the provided size
	if (arr == NULL) {
		buf.reserve(size);
		clear();
	} else { // Consume the provided array
		buf.reserve(size);
		clear();
		put_bytes(reinterpret_cast<const uint8_t*>(arr), size);
	}

#ifdef BB_UTILITY
	name = "";
#endif
}

/**
 * Bytes Remaining
 * Returns the number of bytes from the current read position till the end of the buffer
 *
 * @return Number of bytes from rpos to the end (size())
 */
uint32_t BBuf::bytes_remaining() {
	return size() - rpos;
}

/**
 * Clear
 * Clears out all data from the internal vector (original preallocated size remains), reset_s the positions to 0
 */
void BBuf::clear() {
	rpos = 0;
	wpos = 0;
	buf.clear();
}

/**
 * Clone
 * Allocate an exact copy of the BBuf on the heap and return a pointer
 *
 * @return A pointer to the newly cloned BBuf. NULL if no more memory available
 */
std::unique_ptr<BBuf> BBuf::clone() {
	std::unique_ptr<BBuf> ret = std::make_unique<BBuf>(buf.size());

	// Copy data
	for (uint32_t i = 0; i < buf.size(); i++) {
		ret->put((uint8_t) get(i));
	}

	// Reset positions
	ret->set_rpos(0);
	ret->set_wpos(0);

	return ret;
}

/**
 * Equals, test for data equivilancy
 * Compare this BBuf to another by looking at each byte in the internal buffers and making sure they are the same
 *
 * @param other BBuf to compare to this one
 * @return True if the internal buffers match. False if otherwise
 */
bool BBuf::equals(const BBuf& other) const {
	// If sizes aren't equal, they can't be equal
	if (size() != other.size())
		return false;

	// Compare byte by byte
	uint32_t len = size();
	for (uint32_t i = 0; i < len; i++) {
		if ((uint8_t) get(i) != (uint8_t) other.get(i))
			return false;
	}

	return true;
}

bool BBuf::operator==(const BBuf& other) const {
	return this->equals(other);
}

/**
 * Resize
 * Reallocates memory for the internal buffer of size newSize. Read and write positions will also be reset
 *
 * @param newSize The amount of memory to allocate
 */
void BBuf::resize(uint32_t newSize) {
	buf.resize(newSize);
	rpos = 0;
	wpos = 0;
}

/**
 * Size
 * Returns the size of the internal buffer...not necessarily the length of bytes used as data!
 *
 * @return size of the internal buffer
 */
uint32_t BBuf::size() const {
	return buf.size();
}

// Replacement

/**
 * Replace
 * Replace occurance of a particular uint8_t, key, with the uint8_t rep
 *
 * @param key uint8_t to find for replacement
 * @param rep uint8_t to replace the found key with
 * @param start Index to start from. By default, start is 0
 * @param firstOccuranceOnly If true, only replace the first occurance of the key. If false, replace all occurances. False by default
 */
void BBuf::replace(uint8_t key, uint8_t rep, uint32_t start, bool firstOccuranceOnly) {
	uint32_t len = buf.size();
	for (uint32_t i = start; i < len; i++) {
		uint8_t data = read<uint8_t>(i);
		// Wasn't actually found, bounds of buffer were exceeded
		if ((key != 0) && (data == 0))
			break;

		// Key was found in array, perform replacement
		if (data == key) {
			buf[i] = rep;
			if (firstOccuranceOnly)
				return;
		}
	}
}

// Read Functions

uint8_t BBuf::peek() const {
	return read<uint8_t>(rpos);
}

uint8_t BBuf::get() const {
	return read<uint8_t>();
}

uint8_t BBuf::get(uint32_t index) const {
	return read<uint8_t>(index);
}

void BBuf::get_bytes(uint8_t* buf, uint32_t len) const {
	for (uint32_t i = 0; i < len; i++) {
		buf[i] = read<uint8_t>();
	}
}

char BBuf::get_char() const {
	return read<char>();
}

char BBuf::get_char(uint32_t index) const {
	return read<char>(index);
}

double BBuf::get_double() const {
	return read<double>();
}

double BBuf::get_double(uint32_t index) const {
	return read<double>(index);
}

float BBuf::get_float() const {
	return read<float>();
}

float BBuf::get_float(uint32_t index) const {
	return read<float>(index);
}

uint32_t BBuf::get_int() const {
	return read<uint32_t>();
}

uint32_t BBuf::get_int(uint32_t index) const {
	return read<uint32_t>(index);
}

uint64_t BBuf::get_long() const {
	return read<uint64_t>();
}

uint64_t BBuf::get_long(uint32_t index) const {
	return read<uint64_t>(index);
}

uint16_t BBuf::get_short() const {
	return read<uint16_t>();
}

uint16_t BBuf::get_short(uint32_t index) const {
	return read<uint16_t>(index);
}

// Write Functions

void BBuf::put(BBuf* src) {
	uint32_t len = src->size();
	for (uint32_t i = 0; i < len; i++)
		append<uint8_t>(src->get(i));
}

void BBuf::put(uint8_t b) {
	append<uint8_t>(b);
}

void BBuf::put(uint8_t b, uint32_t index) {
	insert<uint8_t>(b, index);
}

void BBuf::put_bytes(const uint8_t* b, uint32_t len) {
	// Insert the data one byte at a time into the internal buffer at position i+starting index
	for (uint32_t i = 0; i < len; i++)
		append<uint8_t>(b[i]);
}

void BBuf::put_bytes(const uint8_t* b, uint32_t len, uint32_t index) {
	wpos = index;

	// Insert the data one byte at a time into the internal buffer at position i+starting index
	for (uint32_t i = 0; i < len; i++)
		append<uint8_t>(b[i]);
}

void BBuf::put_char(char value) {
	append<char>(value);
}

void BBuf::put_char(char value, uint32_t index) {
	insert<char>(value, index);
}

void BBuf::put_double(double value) {
	append<double>(value);
}

void BBuf::put_double(double value, uint32_t index) {
	insert<double>(value, index);
}
void BBuf::put_float(float value) {
	append<float>(value);
}

void BBuf::put_float(float value, uint32_t index) {
	insert<float>(value, index);
}

void BBuf::put_int(uint32_t value) {
	append<uint32_t>(value);
}

void BBuf::put_int(uint32_t value, uint32_t index) {
	insert<uint32_t>(value, index);
}

void BBuf::put_long(uint64_t value) {
	append<uint64_t>(value);
}

void BBuf::put_long(uint64_t value, uint32_t index) {
	insert<uint64_t>(value, index);
}

void BBuf::put_short(uint16_t value) {
	append<uint16_t>(value);
}

void BBuf::put_short(uint16_t value, uint32_t index) {
	insert<uint16_t>(value, index);
}

// Utility Functions
#ifdef BB_UTILITY
void BBuf::set_name(std::string n) {
	name = n;
}

std::string BBuf::get_name() {
	return name;
}

void BBuf::info() {
	uint32_t length = buf.size();
	std::cout << "BBuf " << name.c_str() << " Length: " << length << ". Info Print" << std::endl;
}

void BBuf::print_ah() {
	uint32_t length = buf.size();
	std::cout << "BBuf " << name.c_str() << " Length: " << length << ". ASCII & Hex Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("0x%02x ", buf[i]);
	}

	std::printf("\n");
	for (uint32_t i = 0; i < length; i++) {
		std::printf("%c ", buf[i]);
	}

	std::printf("\n");
}

void BBuf::print_ascii() {
	uint32_t length = buf.size();
	std::cout << "BBuf " << name.c_str() << " Length: " << length << ". ASCII Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("%c ", buf[i]);
	}

	std::printf("\n");
}

void BBuf::print_hex() {
	uint32_t length = buf.size();
	std::cout << "BBuf " << name.c_str() << " Length: " << length << ". Hex Print" << std::endl;

	for (uint32_t i = 0; i < length; i++) {
		std::printf("0x%02x ", buf[i]);
	}

	std::printf("\n");
}

void BBuf::print_pos() {
	uint32_t length = buf.size();
	std::cout << "BBuf " << name.c_str() << " Length: " << length << " Read Pos: " << rpos << ". Write Pos: "
	        << wpos << std::endl;
}

#endif
