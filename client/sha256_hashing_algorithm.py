'''Sample code'''
import hashlib
print(hashlib.sha256("Pa$$w0rd".encode('UTF-8')).hexdigest())