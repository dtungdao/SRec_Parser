import os
import sys
import re
import collections

from DataLineFormat import *
from DataBlockFormat import *
from S19Struct import *


class S19Parser():
	def __init__(self, s19_file_name, isCalCs):
		self.s19_file = open(s19_file_name, "rt")
		self.isCalCs = isCalCs
		
		self.s19 = self.parser(self.s19_file, self.isCalCs)
		
	def getS19Header(self):
		return self.s19.header
	
	def getS19DataLines(self):
		return self.s19.data_lines
		
	def getS19DataBlocks(self):
		return self.s19.data_blocks
	
	def getS19LineCount(self):
		return self.s19.data_rec_cnt
	
	def getS19ExeStartAddress(self):
		return self.s19.exe_start_addr
	
	def parser(self, s19_file, isCalCs):	
		s19 = S19Struct()
		lines = s19_file.readlines()
		
		block_start_addr = block_end_addr = None
		data_block = []
		
		for line in lines:
			line = line.strip()
			
			# check s-record format
			if(line[0] != 'S'): raise Exception('Wrong S-Record file format at "%s" is not correct' % (line))

			# get the mandatory fields
			record_type = line[0 : 2]
			byte_cnt = int(line[2 : 4], 16)
			cs = int(line[-2:], 16)
			
			# check sum verify
			if(isCalCs):
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
				
				# store data as data line format
				s19.data_lines.append(DataLineFormat(addr, data, cs))
				
				# store data as data block format
				arr_data = re.findall('..', data)
				for byte_addr, byte in zip(range(addr, addr + len(arr_data)), arr_data):			
					if(block_end_addr != None):
						if((byte_addr - block_end_addr) != 1): # transit to new block
							s19.data_blocks.append(DataBlockFormat(block_start_addr, block_end_addr, data_block))

							block_start_addr = None
							block_end_addr = None
							data_block = []
					block_end_addr = byte_addr
						
					if(block_start_addr == None): # this is the first block
						block_start_addr = byte_addr
					   
					data_block.append(int(byte, 16))
			elif(record_type == "S4"):
				pass # This record is reserved
			elif(record_type == "S5"):
				if(s19.data_rec_cnt == None):
					s19.data_rec_cnt = int(line[4 : 4 + (byte_cnt * 2) - 2], 16)
				else: raise Exception('Found more than one "S5" record in file')
			elif(record_type == "S6"):
				if(s19.data_rec_cnt == None): pass
				else: raise Exception('Found more than one "S6" record in file')
			elif(record_type == "S7"):
				s19.exe_start_addr = int(line[4 : 4 + (byte_cnt * 2) - 2], 16)
			elif(record_type == "S8"):
				raise Exception('Record field current not support')
			elif(record_type == "S9"):
				raise Exception('Record field current not support')
		
		# add the last block into struct
		s19.data_blocks.append(DataBlockFormat(block_start_addr, block_end_addr, data_block))		
		
		return s19
	

if __name__ == '__main__':
	parser = S19Parser(s19_file_name=r"C:\Users\ddtkh\Desktop\s19_parser\SRec_Parser\test\sample.s19", 
					   isCalCs=False)
	
	print("Header: " + parser.getS19Header())
	print("S3 line count: " + str(parser.getS19LineCount()))
	print("Start address: 0x%08X" % parser.getS19ExeStartAddress())

	for block in parser.getS19DataBlocks():
		print("Block: ", 
			  hex(block.block_start_addr), 
			  hex(block.block_end_addr), 
			  len(block.block_data))
