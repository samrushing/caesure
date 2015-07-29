// -*- Mode: C++ -*-

#include <stdint.h>
#include <string>

#include "faa.h"

// best I can tell no way to declare an operator() in Cython, otherwise this
//   file would be unecessary.

struct outpoint_t
{
  uint16_t index;
  uint64_t amt;
  std::string oscript;
};

struct compare_outpoint_t
{
  bool operator()(const outpoint_t & a, const outpoint_t & b) const {return a.index < b.index;}
};

typedef FAA<outpoint_t, compare_outpoint_t> index_map_t;
typedef uint8_t hash_t[32];

struct txname_t
{
  hash_t name;
  index_map_t outpoints;
};

struct compare_txname_t
{
  bool operator()(const txname_t & a, const txname_t & b) const { return 0 > memcmp (a.name, b.name, 32); }
};

typedef FAA<txname_t, compare_txname_t> txname_map_t;


static char hexdigits[17] = "0123456789abcdef";
std::ostream& operator<< (std::ostream & stream, const hash_t val)
{
  stream << "<";
  for (int i=0; i < 32; i++) {
    stream << hexdigits[val[i]>>4] << hexdigits[val[i]&0xf];
  }
  stream << ">";
  return stream;
}

std::ostream& operator<< (std::ostream & stream, const struct txname_t & x)
{
  stream << x.name;
  return stream;
}

std::ostream& operator<< (std::ostream & stream, const struct outpoint_t & x)
{
  stream << "." << x.index;
  return stream;
}
