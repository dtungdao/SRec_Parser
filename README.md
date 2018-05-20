# SRec_Parser
S-Record reader and writer suport multi chunk data with un-seamless address
```python
class SrecType():
    def __init__(self):
        self.srec_header = None
        self.srec_chunks = []
        self.srec_cnt = None
        self.exe_start_addr = None
    
    . . .
```
Reference: https://en.wikipedia.org/wiki/SREC_(file_format)

# Usage
main.py
```python
from Srec import SrecWriter
from Srec import SrecReader

wSrec = SrecWriter()
for _ in range(4):
    wSrec.addNewChunk(random.randint(0, 0xFFFFFFFF), 
                      [random.randrange(0, 0xFF) for _ in range(1, random.randint(10, 100000))])
    
    wSrec.writeSrecFile(sys.argv[1], srec_len=28)

for file_name in sys.argv[2:]:
    print("### File: %s" % file_name)
    
    rSrec = SrecReader(file_name, is_validate_cs=True)
    
    for chunk in rSrec.srec.getSrecChunks():
        print("> 0x%08X - 0x%08X | %d byte(s)" % (chunk.chunk_start_addr, 
                                                  chunk.chunk_end_addr, 
                                                  len(chunk.chunk_data)))
    
    print("")
```

```bash
>>> python main.py new_file.s19 new_file.s19
```
