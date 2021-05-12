from django.shortcuts import render

const = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def add(a,b):
    return (a+b)%(2**32)

def rotr(n, d):
    return (n >> d)|(n << (32 - d)) & 0xFFFFFFFF

def shr(num, bits):
    while(bits):
        num=num>>1
        bits=bits-1
    return num

def choice(x,y,z):
    return (x & y) ^ (~x & z)

def maz(x,y,z):
  return (x & y) ^ (x & z) ^ (y & z)

def sig_0(num):
  return (rotr(num,18) ^ rotr(num,7) ^ shr(num,3))
def sig_1(num):
  return (rotr(num,17) ^ rotr(num,19) ^ shr(num,10))
def SIG_0(num):
  return (rotr(num,2) ^ rotr(num,13) ^ rotr(num,22))
def SIG_1(num):
  return (rotr(num,6) ^ rotr(num,11) ^ rotr(num,25))

# Function to convert the text into string of 0 and 1 
def message(msg):
    res = ''
    for char in msg:
      res+=format(ord(char),'08b') #ord functions returns the unicode and format function convert it to binary
    return res

# Function to pad the message into multiple of 512bit length
def padding(msg):
    sz = len(msg);
    pdsz = (448-sz-1)%512
    return msg+"1"+"0"*pdsz + format(sz,'#064b')

# Function to divide the message into blocks of 512bit length
def blocks(msg):
  return [ msg[i:i+512] for i in range(0,len(msg),512)]

def schedule(block):
    return [ block[i:i+32] for i in range(0,len(block),32)]

# Function to convert the string to binary
def message_schedule(blocks):
    return [int(stri,2) for stri in blocks]

# Function to append the message schedule to 64 blocks
def extend_schedule(blocks):
    ans = blocks
    for i in range(16,64):
        ans.append(add(sig_1(ans[i-2]),add(ans[i-7],add(sig_0(ans[i-15]),ans[i-16])))) #Wt = σ1(Wt-2) + Wt-7 + σ0(Wt-15) + Wt-16
    return ans

def sha256(text):
    H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]   #Initial Hash Values
    msginbin = message(text)
    paddedmsg = padding(msginbin)
    msgblocks = blocks(paddedmsg)
    for msgblock in msgblocks:
        H0 = H[:]                                                       #Copying new hash values to H0 at the start of each iteration
        scheduled_words = schedule(msgblock)
        scheduled_words_int = message_schedule(scheduled_words)
        scheduled_words_int_extnd = extend_schedule(scheduled_words_int)
        for i in range(0,64):
            t1 = add(SIG_1(H0[4]),add(choice(H0[4],H0[5],H0[6]),add(H0[7],
                        add(const[i],scheduled_words_int_extnd[i]))))   # T1 = Σ1(e) + choice(e+f+g) + h + K0 + W0
            t2 = add(SIG_0(H0[0]),maz(H0[0],H0[1],H0[2]))               # T2 = Σ0(a) + maz(a,b,c)
            for j in range(1,8):                                        # Shifting all the hash values one stepdown and putting a = T1+T2 and add e to T1
                H0[8-j] = H0[8-j-1]
            H0[0] = add(t1,t2)
            H0[4] = add(H0[4] , t1)
        for i in range(8):                                              #Computing new hash values H = H + H0(prev)
            H[i] = add(H[i],H0[i])
    
    ans = ''
    for i in range(8):
        ans = ans+ hex(H[i])[2:]
    return ans


def calculate_sha256(request):
    if request.method == 'POST':
        text = str(request.POST['text'])
        result = sha256(text)
        return render(request, 'base.html', {'orig': text,'result':result})
    print("none")
    return render(request, 'base.html')

