import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
#s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
s.bind(('', 80))

while True:
	print s.recvfrom(65565)
