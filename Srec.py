import os, sys
import re
import struct
import binascii
import random


class SrecType():
	def __init__(self):
		self.srec_header = None
		self.srec_chunks = []
		self.srec_cnt = None
		self.exe_start_addr = None


class SrecChunkType():
	def __init__(self, chunk_start_addr, chunk_end_addr, chunk_data):
		self.chunk_start_addr = chunk_start_addr
		self.chunk_end_addr = chunk_end_addr
		self.chunk_data = chunk_data
		

class SrecReader():
	def __init__(self, s19_file_name, is_validate_cs):
		self.s19_file = open(s19_file_name, "rt")
		self.is_validate_cs = is_validate_cs
		self.s19 = SrecType()
		self.reader(self.s19, self.s19_file, self.is_validate_cs)

	def getS19Header(self):
		return self.s19.srec_header
		
	def getS19Chunks(self):
		return self.s19.srec_chunks

	def appendS19Chunk(self, new_block):
		for block in self.getS19Chunks():
			if( new_block.chunk_start_addr in range(block.chunk_start_addr, block.chunk_end_addr) ):
				print("Overlap data when adding new Chunk")
				#raise Exception("Overlap data when adding new Chunk")
		self.s19.srec_chunks.append(new_block)

	def getS19LineCount(self):
		return self.s19.srec_cnt
	
	def getS19ExeStartAddress(self):
		return self.s19.exe_start_addr
	
	def reader(self, s19, s19_file, is_validate_cs):
		lines = s19_file.readlines()
		
		chunk_start_addr = chunk_end_addr = None
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
			if(is_validate_cs):
				cs_cal = 0xFF ^ (sum(list(struct.unpack("B"*int(len(line[2 : -2])/2), binascii.unhexlify(line[2 : -2])))) & 0xFF)
				if(cs != cs_cal): raise Exception('Check sum at line "%s" is not correct' % (line))

			if(record_type == "S0"):
				if(s19.srec_header == None):
					s19.srec_header = line[8 : 8 + (byte_cnt * 2) - 6]#.decode('hex')
				else: raise Exception('Found 2 "S0" record in file')
			elif(record_type == "S1"):
				raise Exception('Record field current not support')
			elif(record_type == "S2"):
				raise Exception('Record field current not support')
			elif(record_type == "S3"):
				addr = int(line[4 : 12], 16) # 32-bit Address
				data = line[12 : 12 + (byte_cnt * 2) - 10]
				
				# store data as data block format
				arr_data = list(struct.unpack("B"*int(len(data)/2), binascii.unhexlify(data)))
				for byte_addr, byte in zip(range(addr, addr + len(arr_data)), arr_data):
					if(chunk_end_addr != None):
						if((byte_addr - chunk_end_addr) != 1): # transit to new block
							self.appendS19Chunk(SrecChunkType(chunk_start_addr, chunk_end_addr, data_block))

							chunk_start_addr = None
							chunk_end_addr = None
							data_block = []
					chunk_end_addr = byte_addr
						
					if(chunk_start_addr == None): # this is the first block
						chunk_start_addr = byte_addr
					   
					data_block.append(byte)
			elif(record_type == "S4"):
				pass # This record is reserved
			elif(record_type == "S5"):
				if(s19.srec_cnt == None):
					s19.srec_cnt = int(line[4 : 4 + (byte_cnt * 2) - 2], 16)
				else: raise Exception('Found more than one "S5" record in file')
			elif(record_type == "S6"):
				if(s19.srec_cnt == None): pass
				else: raise Exception('Found more than one "S6" record in file')
			elif(record_type == "S7"):
				s19.exe_start_addr = int(line[4 : 4 + (byte_cnt * 2) - 2], 16)
			elif(record_type == "S8"):
				raise Exception('Record field current not support')
			elif(record_type == "S9"):
				raise Exception('Record field current not support')
		
		# add the last block into struct
		self.appendS19Chunk(SrecChunkType(chunk_start_addr, chunk_end_addr, data_block))


class SrecWriter():
	def __init__(self):
		self.s19 = SrecType()
		
	def addNewChunk(self, start_addr, arr):
		for block in self.s19.srec_chunks:
			if( start_addr in range(block.chunk_start_addr, block.chunk_end_addr) ):
				raise Exception("Overlap data when adding new Chunk")
		self.s19.srec_chunks.append(SrecChunkType(start_addr, start_addr + len(arr), arr))
	
	def writeS19File(self, s19_file_name, srec_len):
		self.s19_file = open(s19_file_name, "wt")
	
		# Write S0 record
		#self.writeS0Record(self.s19.getS19Header(), self.s19_file)
		# write S3 records
		for block in self.s19.srec_chunks:
			self.writeS3Record(block, srec_len, self.s19_file)
		# Write S5 record
		self.writeS5Record(self.s19.srec_cnt, self.s19_file)
		# Write S7 record
		self.writeS7Record(self.s19.exe_start_addr, self.s19_file)
		
		self.s19_file.close()

	def writeS0Record(self, header, s19_file):
		if(header != None):
			line = "S0"
			line += "%02X0000" % ((len(header.encode("hex")) / 2) + 2 + 1)
			line += "%s" % header.encode("hex")
			line += "%02X" % (0xFF ^ (sum([int(num, 16) for num in re.findall('..', line[2:])]) & 0xFF))
			s19_file.write(line + "\n")
		
	def writeS3Record(self, block, srec_len, s19_file):
		addr = block.chunk_start_addr
		
		for arr in [block.chunk_data[idx : idx + srec_len] for idx in range(0, len(block.chunk_data), srec_len)]:
			line = "S3"
			line += "%02X" % (len(arr) + 4 + 1)
			line += "%08X" % addr
			for byte in arr: line += "%02X" % byte
			line += "%02X" % (0xFF ^ (sum([int(num, 16) for num in re.findall('..', line[2:])]) & 0xFF))
			s19_file.write(line + "\n")
			addr += len(arr)

	def writeS5Record(self, cnt, s19_file):
		if(cnt != None):
			line = "S505"
			line += "%08X" % cnt
			line += "%02X" % (0xFF ^ (sum([int(num, 16) for num in re.findall('..', line[2:])]) & 0xFF))
			s19_file.write(line + "\n")
		
	def writeS7Record(self, addr, s19_file):
		if(addr != None):
			line = "S705"
			line += "%08X" % addr
			line += "%02X" % (0xFF ^ (sum([int(num, 16) for num in re.findall('..', line[2:])]) & 0xFF))
			s19_file.write(line + "\n")
		

if __name__ == '__main__':
	wS19 = SrecWriter()
	for _ in range(4):
		wS19.addNewChunk(random.randint(0, 0xFFFFFFFF), [random.randrange(0, 0xFF) for _ in range(1, random.randint(10, 100000))])
	wS19.writeS19File(sys.argv[1], srec_len=28)
	
	for file_name in sys.argv[2:]:
		print("### File: %s" % file_name)
		rS19 = SrecReader(file_name, is_validate_cs=True)
		for block in rS19.getS19Chunks():
			print("> 0x%08X - 0x%08X | %d byte(s)" % (block.chunk_start_addr, block.chunk_end_addr, len(block.chunk_data)))
		print("")