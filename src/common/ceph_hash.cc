
#include "include/types.h"

#include <iostream>
#include <fstream>

/*
 * Robert Jenkin's hash function.
 * http://burtleburtle.net/bob/hash/evahash.html
 * This is in the public domain.
 */
#define mix(a, b, c)						\
	do {							\
		a = a - b;  a = a - c;  a = a ^ (c >> 13);	\
		b = b - c;  b = b - a;  b = b ^ (a << 8);	\
		c = c - a;  c = c - b;  c = c ^ (b >> 13);	\
		a = a - b;  a = a - c;  a = a ^ (c >> 12);	\
		b = b - c;  b = b - a;  b = b ^ (a << 16);	\
		c = c - a;  c = c - b;  c = c ^ (b >> 5);	\
		a = a - b;  a = a - c;  a = a ^ (c >> 3);	\
		b = b - c;  b = b - a;  b = b ^ (a << 10);	\
		c = c - a;  c = c - b;  c = c ^ (b >> 15);	\
	} while (0)

unsigned ceph_str_hash_rjenkins(const char *str, unsigned length)
{
	const unsigned char *k = (const unsigned char *)str;
	__u32 a, b, c;  /* the internal state */
	__u32 len;      /* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = 0x9e3779b9;      /* the golden ratio; an arbitrary value */
	b = a;
	c = 0;               /* variable initialization of internal state */

	/* handle most of the key */
	while (len >= 12) {
		a = a + (k[0] + ((__u32)k[1] << 8) + ((__u32)k[2] << 16) +
			 ((__u32)k[3] << 24));
		b = b + (k[4] + ((__u32)k[5] << 8) + ((__u32)k[6] << 16) +
			 ((__u32)k[7] << 24));
		c = c + (k[8] + ((__u32)k[9] << 8) + ((__u32)k[10] << 16) +
			 ((__u32)k[11] << 24));
		mix(a, b, c);
		k = k + 12;
		len = len - 12;
	}

	/* handle the last 11 bytes */
	c = c + length;
	switch (len) {            /* all the case statements fall through */
	case 11:
		c = c + ((__u32)k[10] << 24);
	case 10:
		c = c + ((__u32)k[9] << 16);
	case 9:
		c = c + ((__u32)k[8] << 8);
		/* the first byte of c is reserved for the length */
	case 8:
		b = b + ((__u32)k[7] << 24);
	case 7:
		b = b + ((__u32)k[6] << 16);
	case 6:
		b = b + ((__u32)k[5] << 8);
	case 5:
		b = b + k[4];
	case 4:
		a = a + ((__u32)k[3] << 24);
	case 3:
		a = a + ((__u32)k[2] << 16);
	case 2:
		a = a + ((__u32)k[1] << 8);
	case 1:
		a = a + k[0];
		/* case 0: nothing left to add */
	}
	mix(a, b, c);

	return c;
}

/*
 * hash function for bingo by jae
 */
#include "rocksdb/db.h"
unsigned ceph_str_hash_bingo(const char *str, unsigned length)
{
	const unsigned char *k = (const unsigned char *)str;

	rocksdb::DB* db;
	rocksdb::Options options;
	options.create_if_missing = true;
	rocksdb::Status status = rocksdb::DB::Open(options, "/var/lib/ceph/bingo.map", &db);
	cerr << "jae: status.ok = " << status.ok() << std::endl;

	return 1;

	// __u32 a, b, c;  /* the internal state */
	// __u32 len;      /* how many key bytes still need mixing */

	// /* Set up the internal state */
	// len = length;
	// a = 0x9e3779b9;      /* the golden ratio; an arbitrary value */
	// b = a;
	// c = 0;               /* variable initialization of internal state */

  // std::string line;
  // ifstream bingomap ("/var/lib/ceph/bingo.map");
  // if (bingomap.is_open())
  // {
	// 	if(getline(bingomap, line)) {
  // 		cerr << "jae: ceph_str_hash_bingo: wanted pg = " << line << '\n' << std::endl;
  //   	bingomap.close();
	// 		return stoi(line);
	// 	} else {
	// 		return 1;
	// 	}
  // }
	// else {
  // 	cerr << "jae: ceph_str_hash_bingo: Unable to open file" << std::endl; 
	// 	return 1;
	// }

	// return c;
}

/*
 * linux dcache hash
 */
unsigned ceph_str_hash_linux(const char *str, unsigned length)
{
	unsigned long hash = 0;

	while (length--) {
		unsigned char c = *str++;
		hash = (hash + (c << 4) + (c >> 4)) * 11;
	}
	return hash;
}


unsigned ceph_str_hash(int type, const char *s, unsigned len)
{
	switch (type) {
	case CEPH_STR_HASH_LINUX:
		return ceph_str_hash_linux(s, len);
	case CEPH_STR_HASH_RJENKINS:
		return ceph_str_hash_rjenkins(s, len);
	case CEPH_STR_HASH_BINGO:
		return ceph_str_hash_bingo(s, len);
	default:
		return -1;
	}
}

const char *ceph_str_hash_name(int type)
{
	switch (type) {
	case CEPH_STR_HASH_LINUX:
		return "linux";
	case CEPH_STR_HASH_RJENKINS:
		return "rjenkins";
	case CEPH_STR_HASH_BINGO:
		return "bingo";
	default:
		return "unknown";
	}
}
