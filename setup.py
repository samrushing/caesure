# -*- Mode: Python -*-

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize

exts = [
    Extension ('caesure.proto', ['caesure/proto.pyx']),
    Extension ('caesure._script', ['caesure/_script.pyx']),
    Extension (
        'caesure._utxo',
        ['caesure/utxo/_utxo.pyx'],
        language="c++",
        extra_compile_args=["-std=c++11"],
        depends=['caesure/utxo/faa.h', 'caesure/utxo/utxo.h', 'caesure/utxo/cons.h']
    ),
    Extension (
        'caesure._utxo_scan',
        ['caesure/utxo/_utxo_scan.pyx'],
        language="c++",
        extra_compile_args=["-std=c++11"]
    ),
]

import os

if os.path.isfile ('/usr/local/lib/libsecp256k1.a'):
    exts.append (
        Extension (
            "caesure.secp256k1",
            ["caesure/ecdsa/secp256k1.pyx"],
            include_dirs=['/usr/local/include'],
            libraries=['secp256k1', 'gmp', 'z'],
            extra_link_args = ['-Wl,-rpath,/usr/local/lib'],
        )
    )

## edit bitcoin.py as well (search for 'ecdsa_cryptopp').
# cryptopp = '/home/rushing/src/crypto++'
# exts.append (
#     Extension (
#         "caesure.cryptopp",
#         ["caesure/ecdsa/cryptopp.pyx", "caesure/ecdsa/cryptopp_wrap.cpp"],
#         include_dirs=[cryptopp],
#         library_dirs=[cryptopp],
#         libraries=['cryptopp'],
#         language="c++",
#     )
# )

# XXX re-tag shrapnel & require the correct version here. [for coro.ssl.openssl.ecdsa]
setup (
    name             = 'caesure',
    version          = '0.1',
    description      = 'bitcoin node',
    author           = "Sam Rushing",
    packages         = ['caesure', 'caesure.utxo'],
    ext_modules      = cythonize (exts),
    install_requires = ['cython>=0.20.2'],
    license          = 'Simplified BSD',
    #cmdclass = {'build_ext': build_ext},
    scripts = ['scripts/caesure'],
)
