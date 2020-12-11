
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

data = b'255044462d312e350a25d0d4c5d80a34'.decode('hex')
ciphertext = "d06bf9d0dab8e8ef880660d2af65aa82"
iv= '09080706050403020100A2B2C2D2E2F2'.decode('hex')


f = open('./output','rUb')
for line in f:
    key = line.strip()
    key = key.decode("hex")
    cipher = AES.new(key, AES.MODE_CBC,iv)
    ct_bytes = cipher.encrypt(pad(data,16))
    if ciphertext == ct_bytes.encode('hex')[0:32]:
       print "[*] Match Key: "+ key.encode('hex')
    
   
