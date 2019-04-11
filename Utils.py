import threading
import struct

addressColor = '#757575'
opcodeColor = '#1B5E20'
nameColor = '#1A237E'
intColor = '#005B2A'
locColor = 'red'
memColor = '#E65100'
idColor = '#1A237E'
commentColor = 'black'
dataColor = '#1B5E20' 
typeColor = '#0D47A1'
opColor = '#023E5E' 
highlightColor = 'yellow'
selectedColor = '#ffffff'


def runMultiThread(listObjs, target):
    lock = threading.Lock()
    numFuncs = len(listObjs)
    for i in range(0, numFuncs, 5):
        obj1 = None
        obj2 = None
        obj3 = None
        obj4 = None
        obj5 = None
        t1 = None
        t2 = None
        t3 = None
        t4 = None
        t5 = None
        if i < numFuncs:
            obj1 = listObjs[i]
        if i + 1 < numFuncs:
            obj2 = listObjs[i + 1]
        if i + 2 < numFuncs:
            obj3 = listObjs[i + 2]
        if i + 3 < numFuncs:
            obj4 = listObjs[i + 3]
        if i + 4 < numFuncs:
            obj5 = listObjs[i + 4]
        if obj1:
            t1 = threading.Thread(target=target, args=(obj1, lock,))
            t1.start()
        if obj2:
            t2 = threading.Thread(target=target, args=(obj2, lock,))
            t2.start()
        if obj3:
            t3 = threading.Thread(target=target, args=(obj3, lock,))
            t3.start()
        if obj4:
            t4 = threading.Thread(target=target, args=(obj4, lock,))
            t4.start()
        if obj5:
            t5 = threading.Thread(target=target, args=(obj5, lock,))
            t5.start()
        if t1:
            t1.join()
        if t2:
            t2.join()
        if t3:
            t3.join()
        if t4:
            t4.join()
        if t5:
            t5.join()


relate_registers = [['RAX', 'EAX', 'AH', 'AL'], ['RBX', 'EBX', 'BH', 'BL'],
                    ['RCX', 'ECX', 'CH', 'CL'], ['RDX', 'EDX', 'DH', 'DL'],
                    ['RSI', 'ESI', 'SH', 'SL'], ['RDI', 'EDI', 'DH', 'DL'], ['RBP', 'EBP'], ['RSP', 'ESP'],
                    ['RIP', 'EIP']]

typeBySize = {8: 'byte', 16: 'short', 32: 'int', 64: 'long'}
sizeByType = {'byte': 1, 'short': 2, 'int': 4, 'long': 8}


def formatData(data):
    if len(data) == 1:
        value = struct.unpack('<B', data)[0]
    elif len(data) == 2:
        value = struct.unpack('<H', data)[0]
    elif len(data) == 4:
        value = struct.unpack('<I', data)[0]
    elif len(data) == 8:
        value = struct.unpack('<Q', data)[0]
    return value
