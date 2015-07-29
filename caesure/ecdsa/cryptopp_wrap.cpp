// sample.cpp

#include <string>
//#include <vector>
//#include <iostream>

#include "osrng.h"
#include "files.h"
#include "filters.h"
#include "cryptlib.h"
//#include "aes.h"
//#include "eax.h"

//#include "asn.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
//#include "oids.h"
//#include "ida.h"
//#include "dsa.h"

using namespace CryptoPP;

//
// simple C interface.
// 

extern "C" {

extern int
_ecdsa_verify (std::string *pub, std::string * data, std::string * sig)
{
  try {
    ECDSA<ECP, SHA256>::PublicKey p;
    p.Load (StringSource (*pub, true, NULL).Ref());
    ECDSA<ECP, SHA256>::Verifier v (p);
    return v.VerifyMessage (
      (const byte *) data->data(), data->size(),
      (const byte *) sig->data(), sig->size()
    );
  } catch (...) {
    return -1;
  }
}

}
