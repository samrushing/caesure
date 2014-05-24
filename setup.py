# -*- Mode: Python -*-

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

exts = [
    Extension ('caesure.proto', ['caesure/proto.pyx']),
    Extension ('caesure._script', ['caesure/_script.pyx']),
]

setup (
    name             = 'caesure',
    version          = '0.1',
    description      = 'bitcoin node',
    author           = "Sam Rushing",
    packages         = ['caesure'],
    ext_modules      = exts,
    install_requires = ['cython>=0.18'],
    license          = 'Simplified BSD',
    cmdclass = {'build_ext': build_ext},
)
