import hmac
import hashlib 
import sys

HM = hmac.new(b"ABCDEFGHIJKLMNOP"*4, sys.argv[1], hashlib.sha256)
print(HM.hexdigest())
