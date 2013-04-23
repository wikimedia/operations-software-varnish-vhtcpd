#!/bin/sh -ex

autoreconf --install --symlink && ./configure $*
