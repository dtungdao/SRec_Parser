import os, sys
import re
import collections


class S19Parser():
	class S19Struct():
		header = None
		data = dict()
		line_cnt = None
		start_addr = None
		cs = None

	def __init__(self, s19_file_name, isCalCk):
		self.s19_file = open(s19_file_name, "rt")
		self.isCalCk = isCalCk
		
		self.s19 = self.parser(self.s19_file, self.isCalCk)
		
	def getS19Header(self):
		return self.s19.header
	
	def getS19Data(self):
		return self.s19.data
	
	def getS19LineCount(self):
		return self.s19.line_cnt
	
	def getS19StartAddress(self):
		return self.s19.start_addr
	
	def parser(self, s19_file, isCalCk):
		s19 = S19Parser.S19Struct()
		lines = s19_file.readlines()
		
		for line in lines:
			line = line.strip()

			record_type = line[0 : 2]
			byte_cnt = int(line[2 : 4], 16)
			cs = int(line[-2:], 16)
			
			# check sum verify
			if(isCalCk):
				cs_cal = 0xFF ^ (sum([int(num, 16) for num in re.findall('..', line[2 : -2])]) & 0xFF)
				if(cs != cs_cal): raise Exception('Check sum at line "%s" is not correct' % (line))
			
			if(record_type == "S0"):
				if(s19.header == None):
					s19.header = line[8 : 8 + (byte_cnt * 2) - 4].decode('hex')
				else: raise Exception('Found 2 "S0" record in file')
			elif(record_type == "S1"):
				raise Exception('Record field current not support')
			elif(record_type == "S2"):
				raise Exception('Record field current not support')
			elif(record_type == "S3"):
				addr = int(line[4 : 12], 16) # 32-bit Address
				data = line[12 : 12 + (byte_cnt * 2) - 10]
				if(addr not in s19.data): s19.data[addr] = data
				self.data.cs = cs
			elif(record_type == "S4"):
				pass # This record is reserved
			elif(record_type == "S5"):
				if(s19.header == None): pass
				else: raise Exception('Found more than one "S5" record in file')
			elif(record_type == "S6"):
				if(s19.header == None): pass
				else: raise Exception('Found more than one "S6 record in file')
			elif(record_type == "S7"):
				s19.start_addr = int(line[4 : 4 + (byte_cnt * 2) - 2], 16)
			elif(record_type == "S8"):
				raise Exception('Record field current not support')
			elif(record_type == "S9"):
				raise Exception('Record field current not support')
			
		return s19
	

if __name__ == '__main__':
	parser = S19Parser(s19_file_name=r"C:\Users\ddtkh\Desktop\s19_parser\XMC24vLow.s19", 
					   isCalCk=False)
	
	print("Header: " + parser.getS19Header())
	print("S3 line count: %d" % parser.getS19LineCount() if parser.getS19LineCount() != None else 0)
	print("Start address: 0x%08X" % parser.getS19StartAddress())
	
	#print(parser.getS19Data()[int('00FE44FF', 16)])
	
	for key, item in collections.OrderedDict(sorted(parser.getS19Data().items())).iteritems():
		print(hex(key), item)