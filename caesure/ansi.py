# -*- Mode: Python; indent-tabs-mode: nil -*-

import coro

W = coro.write_stderr

# bright = 30 + n:
#   0    1    2      3     4     5      6    7
# Black Red Green Yellow Blue Magenta Cyan White

def ansi (m, color):
    return (('\x1b[1;%dm' % color) + m + '\x1b[0m')

def WT (m):
    "packet to (red-shifted)"
    W (ansi (m, 31))

WR = WT

def WF (m):
    "packet from (blue-shifted)"
    W (ansi (m, 34))

WB = WF

def WY (m):
    W (ansi (m, 33))

