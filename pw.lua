local linux = require 'linux'

io.write('username: ')
local user = io.read()

local t = linux.getpwnam(user)
local s = linux.getspnam(user)
local salt = string.match(s.sp_pwdp, '(%$[^%$]+%$[^%$]+%$)')

local pw = linux.getpass('password: ')

cpw = linux.crypt(pw, salt)

if cpw == s.sp_pwdp then
	print('match')
else
	print('no match')
end

