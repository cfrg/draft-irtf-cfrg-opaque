import sys

def ByteArrayToInteger(k,numBytes=32):
    try:
        k_list = [ord(b) for b in k]
    except:
        k_list = [b for b in k]
 
    if numBytes < len(k_list):
    	numBytes = len(k_list)
    	
    return sum((k_list[i] << (8 * i)) for i in range(numBytes))

def IntegerToByteArray(k,numBytes = 32):
    result = bytearray(numBytes)
    for i in range(numBytes):
        result[i] = (k >> (8 * i)) & 0xff
    return result
