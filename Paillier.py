# -*- coding: utf-8 -*-


from Crypto.Util import number
import math
from Crypto.Random import random
       

class Paillier:
    def __init__(self,length):
        self.length = length
        self.bits = length //2
        self.key_gen()
        
    def __get_p_q(self):
        p = number.getPrime(self.bits)
        q = number.getPrime(self.bits)
        return p,q
    
    def __inv(self,a, m) : 
        m0 = m 
        x0 = 0
        x1 = 1
        if (m == 1) :
            return 0
  
        # Apply extended Euclid Algorithm 
        while (a > 1) : 
            # q is quotient 
            q = a // m 
            t = m 
  
            # m is remainder now, process  
            # same as euclid's algo 
            m = a % m 
            a = t 
            t = x0 
            x0 = x1 - q * x0 
            x1 = t 
      
        # Make x1 positive 
        if (x1 < 0) : 
            x1 = x1 + m0 
        return x1

    
    def key_gen(self):
        eq = 1
        while(eq == 1):
            p,q = self.__get_p_q()
            if(p!=q):
                eq = 0
        self.n = p*q
        self.nsq = self.n*self.n
        self.g = self.n + 1
        self.__lamb = (p-1)*(q-1)
        self.__miu = self.__inv(self.__lamb,self.n)
        
    
    def encrypt(self,m):
        r = random.randint(1,self.n-1)
        g_m = pow(self.g, m, self.nsq)
        r_n = pow(r, self.n, self.nsq)
        return (g_m * r_n) % self.nsq
    
    def decrypt(self,e):
        arg = pow(e, self.__lamb, self.nsq)
        L = (arg -1) // self.n
        return (L * self.__miu) % self.n
    
    def secure_addition(self,e1,e2):
        return e1 * e2 % self.nsq
    
    def secure_scalar_multiplication(self,e,c):
        return pow(e,c,self.nsq)
    
    def secure_subtraction(self,e1,e2):
        e_tmp = pow(e2, self.n -1, self.nsq)
        return (e1 * e_tmp) % self.nsq

def testsys(obj):
    
    plain = random.randrange(0,obj.n)
    plain_enc = obj.encrypt(plain)
    plain_dec = obj.decrypt(plain_enc)
    
    if(plain_dec == plain):
        print("Encryption and Decryption work")
    else:
        print("Error in encryption or decryption")
        
    plain2 = random.randrange(0,obj.n)
    plain2_enc = obj.encrypt(plain2)
    plain2_dec = obj.decrypt(plain2_enc)
    
    sec_add = obj.secure_addition(plain_enc,plain2_enc)
    sec_add_dec = obj.decrypt(sec_add)
    
    if(sec_add_dec == (plain + plain2) % obj.n):
        print("Secure additon works")
    else:
        print("Error in secure addition")
        
    scalar = random.randrange(0,obj.n)
    sec_mul = obj.secure_scalar_multiplication(plain_enc, scalar)
    sec_mul_dec = obj.decrypt(sec_mul)
    
    if(sec_mul_dec == (plain*scalar) % obj.n):
        print("Secure Scalar Multiplication Works")
    else:
        print("Error in secure scalar multiplication")
        
    if(plain > plain2):
        sec_sub = obj.secure_subtraction(plain_enc,plain2_enc)
        dif = plain - plain2
    else:
        sec_sub = obj.secure_subtraction(plain2_enc,plain_enc)
        dif = plain2 - plain
    
    sec_sub_dec = obj.decrypt(sec_sub)
    
    if(sec_sub_dec == dif):
        print("Secure subtraction works")
    else:
        print("Error in secure subtraction")
    
    
class A_party:
    def __init__(self,crypto,l,k):
        self.crypto = crypto
        self.l = l
        self.k = k
        
    def __inv(self,a, m) : 
        m0 = m 
        x0 = 0
        x1 = 1
        if (m == 1) :
            return 0
  
        # Apply extended Euclid Algorithm 
        while (a > 1) : 
            # q is quotient 
            q = a // m 
            t = m 
  
            # m is remainder now, process  
            # same as euclid's algo 
            m = a % m 
            a = t 
            t = x0 
            x0 = x1 - q * x0 
            x1 = t 
      
        # Make x1 positive 
        if (x1 < 0) : 
            x1 = x1 + m0 
        return x1
    
        
    def set_a_b_enc(self,a_enc,b_enc):
        self.a_enc = a_enc
        self.b_enc = b_enc
        
    def step_1(self):
        bits = self.l + self.k + 1
        self.r = random.getrandbits(bits)
        r_enc = self.crypto.encrypt(self.r)
        dif = self.crypto.secure_subtraction(self.a_enc,self.b_enc)
        x_enc = self.crypto.secure_addition(dif,r_enc)
        return x_enc  
    
    def step_3(self,x_l_enc):
        rx_enc = []
        for i in range(self.l):
            if((self.r>>i)&1==0):
                rx_enc.append(x_l_enc[i])
            else:
                enc_1 = self.crypto.encrypt(1)
                x_i_inv = self.__inv(x_l_enc[i],self.crypto.nsq)
                res = self.crypto.secure_addition(enc_1,x_i_inv)
                rx_enc.append(res) 
        return rx_enc
                
    def step_4(self):
        self.delta = random.randint(0,1)
    
    def step_5_12(self,rx_enc):
        c_list =[]
        if(self.delta == 0):
            c0_enc = 1
            for i in range(self.l):
                c0_enc *= self.crypto.secure_addition(c0_enc,rx_enc[i])
            bl = random.randint(1,2**self.l)
            c0 = self.crypto.secure_scalar_multiplication(c0_enc,bl)
            c_list.append(c0)
            for i in range(1,self.l):
                randomint = random.randint(1,2**self.l)
                randomint_enc = self.crypto.encrypt(randomint)
                c_list.append(randomint_enc)
        else:
            enc_minus1 = self.crypto.encrypt(self.crypto.n-1)
            for i in range(self.l):
                prod =1
                for j in range(i+1,self.l):
                    prod *= self.crypto.secure_addition(prod,rx_enc[j])
                prod_sq = self.crypto.secure_scalar_multiplication(prod,2)
                c_i_1 = self.crypto.secure_addition(enc_minus1,rx_enc[i])
                c_i_2 = self.crypto.secure_addition(c_i_1,prod_sq)
                randomint = random.randint(1,2**self.l)
                c_i_fin = self.crypto.secure_scalar_multiplication(c_i_2,randomint)
                c_list.append(c_i_fin)
        random.shuffle(c_list)
        return c_list
    
    def step_15(self,deltaB_enc):
        res = 0
        if(self.delta ==0):
            res = deltaB_enc
        else:
            enc1 = self.crypto.encrypt(1)
            deltaB_enc_inv = self.__inv(deltaB_enc,self.crypto.nsq)
            res = self.crypto.secure_addition(enc1,deltaB_enc_inv)
        return res
            
        

class B_party:
    def __init__(self, crypto,l):
        self.crypto = crypto
        self.l = l
    
    def step_2(self,x_enc):
        x = self.crypto.decrypt(x_enc)
        x_l_enc = []
        for i in range(self.l):
            x_i_enc = self.crypto.encrypt((x>>i)&1)
            x_l_enc.append(x_i_enc)
        return x_l_enc
    
    def step_13(self,c_list):
        deltaB = 0
        for i in range(len(c_list)):
            c_i_dec = self.crypto.decrypt(c_list[i])
            if(c_i_dec ==0):
                deltaB = 1
                break
        deltaB_enc = self.crypto.encrypt(deltaB)
        return deltaB_enc
    
def EQT1(cryptosys,a_enc,b_enc,l,k):
    A = A_party(cryptosys,l,k)
    B = B_party(cryptosys,l)
    A.set_a_b_enc(a_enc,b_enc)
    x_enc = A.step_1()
    x_l_enc = B.step_2(x_enc)
    rx_enc = A.step_3(x_l_enc)
    A.step_4()
    c_list = A.step_5_12(rx_enc)
    deltaB_enc = B.step_13(c_list)
    res = A.step_15(deltaB_enc)
    final = cryptosys.decrypt(res)
    if(final ==1):
        print("The numbers are equal")
    else:
        print("The numbers are not equal")
        
cryptosys = Paillier(2048)
a = random.randint(1,1024)
b = random.randint(1,1024)
a_enc = cryptosys.encrypt(a)
b_enc = cryptosys.encrypt(b)
EQT1(cryptosys,a_enc,b_enc,10,40)