from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random
import time,sys

import setting

N = setting.N
t=setting.t

class DHPVSS():
    
    def hash(self,obj):
        return self.group.hash(str(obj), ZR)

    def __init__(self, groupObj):        
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
    
        self.sks=[self.group.random(ZR) for i in range(0,N+1)]
        self.pks=[self.g**self.sks[i] for i in range(0,N+1)]
        self.omega=[self.g**self.sks[i] for i in range(0,N+1)]
        self.S=self.group.random(G1)
        self.codeword = [self.group.init(ZR, 1)]
        for i in range(1, N + 1):
            vi = self.group.init(ZR, 1)
            for j in range(1, N + 1):
                if i != j:
                    vi = vi * 1 / (self.group.init(ZR, i) - j)                    
            self.codeword.append(vi)
        # print(self.codeword)
        self.index=1
        self.alphas=[self.group.random(ZR) for i in range(0,N+1)]

    def evaluate_polynomial(self, coefficients, x):
        result = 0
        for i, coeff in enumerate(reversed(coefficients)):
            result += coeff * (x ** i)
        return result

    def distribute(self):
        starttime = time.time()
        s=self.group.random(ZR)        
        self.S=self.g**s
        
        
        shares = self.util.genShares(s, t, N)
        A=[0]
        A.extend([self.g ** shares[i] for i in range(1, N+1)])
        # print(shat)
        C=[0]
        C.extend([(self.pks[i] ** self.sks[self.index]) * A[i] for i in range(1, N+1)])
        
        # mstar=self.group.init(ZR, 1)      #todo
        coeffs = [self.group.hash(str(self.pks)+str(C)+str(i), ZR) for i in range(1, N-t-1)]

        V=self.group.init(G1, 1)
        U=self.group.init(G1, 1)
        for i in range(1,  N+1):            
            mstar= self.evaluate_polynomial(coeffs, self.group.init(ZR, i))
            V = V* (C[i]**(mstar*self.codeword[i]))
            U = U* (self.pks[i]**(mstar*self.codeword[i]))
        
        w = self.group.random(ZR)        
        c = self.group.hash(str(U)+str(V), ZR)        
        z,a1,a2=self.g**w, U**w, w - self.sks[self.index] * c  
        PfSh=[z, a1, a2]
        dist={"C":C,"PfSh":PfSh}
        print("DHPVSS distribute cost %.3fs, size %.2fkB"%(time.time()- starttime, len(str(dist))/1024.))
        return dist


    def verify(self,dist):
        starttime = time.time()
        mstar=self.group.init(ZR, 1)      #todo
        coeffs = [self.group.hash(str(self.pks)+str(dist["C"])+str(i), ZR) for i in range(1, N-t-1)]
        V=self.group.init(G1, 1)
        U=self.group.init(G1, 1)
        for i in range(1,  N+1):
            mstar= self.evaluate_polynomial(coeffs, self.group.init(ZR, i))
            V = V* (dist["C"][i]**(mstar*self.codeword[i]))
            U = U* (self.pks[i]**(mstar*self.codeword[i]))
        
        # Check DLEQ proofs
        c = self.group.hash(str(U)+str(V), ZR)       
        
        if dist["PfSh"][0] != (self.g**dist["PfSh"][2]) * (self.pks[self.index]**c) or \
            dist["PfSh"][1] != (U**dist["PfSh"][2]) * (V**c):
            print("fail to verify")
            return False
               
        print("DHPVSS verification cost %.3fs"%(time.time()- starttime))
        
        return True

    def preRecon(self, Ci, i):
        Ai= Ci/(self.pks[self.index]**self.sks[i])
        w = self.group.random(ZR)        
        c = self.group.hash(str(self.pks[self.index])+str(Ci-Ai), ZR)        
        z,a1,a2=self.g**w, self.pks[i]**w, w - self.sks[self.index] * c  
        PfDec=[z, a1, a2]
        reconi={"Ai":Ai,"PfDec":PfDec}
        return reconi
        

    def reconstruct(self, recon, C):
        starttime = time.time()
        for i in recon:
            reconi = recon[i]
            c = self.group.hash(str(self.pks[self.index])+str(C[i]-reconi["Ai"]), ZR)       
            
            if reconi["PfDec"][0] != (self.g**reconi["PfDec"][2]) * (self.pks[self.index]**c) or \
                reconi["PfDec"][1] != ((self.pks[i])**reconi["PfDec"][2]) * ((C[i]-reconi["Ai"])**c):
                print("fail to verify")
                return False
        
        indexArr = [i for i in range(1,N+1)]

        # random.shuffle(indexArr)
        indexArr=indexArr[0:t]
        y = self.util.recoverCoefficients(indexArr)
        z=self.group.init(G1,1)
        for i in indexArr:    
            z *= recon[i]["Ai"]**y[i]    
        print("DHPVSS reconstruction cost %.3fs size: %.2fkB"%((time.time()- starttime), len(str(recon))/1024.))
        if self.S!=z: 
            print("DHPVSS fail to reconstruct")
            return -2
        return 1


if __name__ == "__main__":    
    
    
    groupObj = PairingGroup("SS512")
    hep = DHPVSS(groupObj)
    dist = hep.distribute()
    hep.verify(dist)
    recon={}
    for i in range(1, t+1):
        recon[i]=hep.preRecon(dist["C"][i],i)
    hep.reconstruct(recon, dist["C"])


