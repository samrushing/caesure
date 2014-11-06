Installation (Ubuntu Trusty 14.04)
==================================

Assuming a fresh system:

```
$ sudo apt-get install build-essential python-dev python-pip libssl-dev
$ sudo pip install cython
$ git clone https://github.com/ironport/shrapnel.git
$ cd shrapnel
$ python setup.py build
$ sudo python setup.py install
$ cd ..
$ git clone https://github.com/samrushing/caesure.git
$ cd caesure
$ python setup.py build
$ sudo python setup.py install
```
