local linux = require 'linux'

local libm, error = linux.dlopen('/usr/lib64/libm.so.6', 'lazy')
print(libm, error)

local f, error = libm.floor
print(f, error)
print(linux.dlsym(libm, 'floor'))
