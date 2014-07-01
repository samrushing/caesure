# -*- Mode: Python -*-

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

# XXX would be nice to probe for what libraries are present and
#     build the best choice automatically.

#cryptopp = "/homes/sam/src/crypto++"

exts = [
    Extension ('caesure.proto', ['caesure/proto.pyx']),
    Extension ('caesure._script', ['caesure/_script.pyx']),
    Extension ('caesure.txfaa', ['caesure/txfaa.pyx'], language="c++"),
    #Extension (
    #    "caesure.cryptopp",
    #    ["caesure/cryptopp.pyx", "caesure/cryptopp_wrap.cpp"],
    #    include_dirs=[cryptopp],
    #    library_dirs=[cryptopp],
    #    libraries=['cryptopp'],
    #    language="c++",
    #),
    #Extension (
    #    "caesure.secp256k1",
    #    ["caesure/secp256k1.pyx"],
    #    include_dirs=['/usr/local/include'],
    #    libraries=['secp256k1', '/usr/lib64/libgmp.so.3', 'z'],
    #    extra_link_args = ['-Wl,-rpath,/usr/local/lib'],
    #),
]

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
)
