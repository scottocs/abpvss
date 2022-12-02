from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random
import time,sys
import setting



N = setting.N
t=setting.t


class SCRAPE():
    def dleq(self, g, y1, pks, y2, shares):
        """ DLEQ... discrete logarithm equality
        Proofs that the caller knows alpha such that y1[i] = x1[i]**alpha and y2[i] = x2[i]**alpha
        without revealing alpha.
        """
        w = self.group.random(ZR)
        z=[0 for i in range(0,len(y1))]
        a1=[0 for i in range(0,len(y1))]
        a2=[0 for i in range(0,len(y1))]
        c = self.group.hash(str(y1)+str(y2), ZR)
        
        for i in range(1, len(z)):
            a1[i] = g**w
            a2[i] = pks[i]**w        
            z[i] = w - shares[i] * c    
        
        return {"g":g, "y1":y1, "pks":pks, "y2":y2, "c":c, "a1":a1, "a2":a2, "z":z}


    def dleq_verify(self, g, y1, pks, y2, c, a1, a2, z):
        for i in range(1, N+1):
            if a1[i] != (g**z[i]) * (y1[i]**c):# or a2 !=pks** z[i] * y2[i] **c:
                return False
        return True



    # setup()
    def __init__(self, groupObj):        
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()
        
        # shareholders are in [1, N]
        self.sks=[self.group.random(ZR) for i in range(0,N+1)]
        self.pks=[self.gp**self.sks[i] for i in range(0,N+1)]

           
    def distribute(self):
        s=self.group.random(ZR)
        self.S=self.gp**s

        shares = self.util.genShares(s, t, N)
        # print(s,shares,len(shares))
        vs=[0]
        vs.extend([self.g ** shares[i] for i in range(1, N+1)])
        # print(shat)
        shat=[0]
        shat.extend([self.pks[i]** shares[i] for i in range(1, N+1)])
        
        res={"shat":shat,"vs":vs}
        # print("GT",len(str(self.group.random(GT))))
        # print("G1",len(str(self.group.random(G1))))
        # print("G2",len(str(self.group.random(G2))))
        
        print("dis message size:",len(str(res)))
        return res


    def verify(self, dis):
        starttime = time.time()
        
        for i in range(1, N+1):
            if pair(self.g,dis["shat"][i]) != pair(dis["vs"][i],self.pks[i]):
                return False


        # reed solomon check        
        v=self.group.init(G1,1)
        codeword=[self.group.init(ZR,1)]
        for i in range(1, N+1):
            vi = self.group.init(ZR,1)
            for j in range(1,N+1):
                if i!=j:
                    vi=vi*1/(i-j)  
            codeword.append(self.group.init(ZR,vi))
        for i in range(1, N+1):
            v=v * (dis["vs"][i]**codeword[i])
        if v != self.group.init(G1,1):
            return False
        print("SCRAPE DBS verification cost ",time.time()- starttime)                 
        return True

    def reconstruct(self,dis):
        # g^s sent by shareholders
        stidle=[self.group.init(G2,1)]
        for i in range(1, N+1):
            stidle.append(dis["shat"][i]**(1/self.sks[i]))
        
        recon={}
        recon["stidle"]=stidle
        print("rec message size:",len(str(recon)))        
        
        # Check Pairing by the recover
        starttime=time.time()
        for i in range(1, N+1):
            if pair(self.pks[i], stidle[i]) != pair(self.gp, dis["shat"][i]):
                return -1
        print("SCRAPE DBS reconstruction verification cost ",time.time()- starttime)

        indexArr = [i for i in range(1,N+1)]

        random.shuffle(indexArr)
        indexArr=indexArr[0:t]
        y = self.util.recoverCoefficients(indexArr)
        z=self.group.init(G2,1)
        for i in indexArr:    
            z *= stidle[i]**y[i]    

        if self.S!=z: 
            return -2
        return z

groupObj = PairingGroup(setting.curveName)
scrape = SCRAPE(groupObj)
print("N=%d,t=%d"%(N,t))
dis= scrape.distribute()
# print(scrape.verify(dis["shat"], dis["vs"]))
print(scrape.verify(dis))
scrape.reconstruct(dis)


