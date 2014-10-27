# -*- Mode: Python -*-

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

exts = [
    Extension ('caesure.proto', ['caesure/proto.pyx']),
    Extension ('caesure._script', ['caesure/_script.pyx']),
    Extension ('caesure.txfaa', ['caesure/txfaa.pyx'], language="c++"),
]

import os

if os.path.isfile ('/usr/local/lib/libsecp256k1.a'):
    if os.uname()[0] == 'Darwin':
        # needed for -rpath to work.
        os.environ['MACOSX_DEPLOYMENT_TARGET'] = '10.9'
    exts.append (
        Extension (
            "caesure.secp256k1",
            ["caesure/secp256k1.pyx"],
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
#         ["caesure/cryptopp.pyx", "caesure/cryptopp_wrap.cpp"],
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
    packages         = ['caesure'],
    ext_modules      = exts,
    install_requires = ['cython>=0.20.2'],
    license          = 'Simplified BSD',
    cmdclass = {'build_ext': build_ext},
    scripts = ['scripts/caesure', 'scripts/catlog'],
)
