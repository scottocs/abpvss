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


    # setup()
    def __init__(self, groupObj):        
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()
        
        # shareholders are in [1, N]
        self.sks=[self.group.random(ZR) for i in range(0,N+1)]
        self.pks=[self.g**self.sks[i] for i in range(0,N+1)]
        self.S=self.group.random(G1)
        self.codeword=[self.group.init(ZR,1)]
        for i in range(1, N+1):            
            vi = self.group.init(ZR,1)
            for j in range(1,N+1):
                if i!=j:
                    vi=vi*1/(self.group.init(ZR, i)-j)  
                    # print(vi,i,j)
            self.codeword.append(vi)
        # self.util.recoverCoefficients([i for i in range(1, self.cpabe.N+1)])

    def distribute(self):
        ts=time.time()
        s=self.group.random(ZR)        
        self.S=self.g**s

        shares = self.util.genShares(s, t, N)
        # print(s,shares,len(shares))
        vs=[0]
        vs.extend([self.gp ** shares[i] for i in range(1, N+1)])
        # print(shat)
        shat=[0]
        shat.extend([self.pks[i]** shares[i] for i in range(1, N+1)])
        
        # DLEQ proofs
        w = self.group.random(ZR)
        z,a1,a2=[0 for i in range(0,len(shares))],[0 for i in range(0,len(shares))],[0 for i in range(0,len(shares))]
        c = self.group.hash(str(vs)+str(shat), ZR)
        
        for i in range(1, len(z)):
            a1[i] = self.gp**w
            a2[i] = self.pks[i]**w        
            z[i] = w - shares[i] * c    
        
        dleqPrfs= {"c":c, "a1":a1, "a2":a2, "z":z}
        
        dist=dleqPrfs.copy()
        dist["shat"]=shat
        dist["vs"]=vs
        print("distribute message size %.2fKB"%(len(str(dist))/1024.))
        print("ScrapeDDH distribution cost %.2fs"%(time.time()- ts))
        return dist


    def verify(self,dist):
        starttime = time.time()
        # Check DLEQ proofs
        c = self.group.hash(str(dist["vs"])+str(dist["shat"]), ZR)
        for i in range(1, N+1):
            if dist["a1"][i] != (self.gp**dist["z"][i]) * (dist["vs"][i]**c)\
                or dist["a2"][i] !=self.pks[i]** dist["z"][i] * (dist["shat"][i] **c):
                return False

        # reed solomon check
        v=self.group.init(G2,1)
        
        for i in range(1, N+1):
            v=v * (dist["vs"][i]**self.codeword[i])
        assert v == self.group.init(G2,1)            
        print("ScrapeDDH verification cost %.2fs"%(time.time()- starttime))
        return True

    def reconstruct(self, dist):

        # DLEQ proofs by shareholders
        stidle=[self.group.init(G1,1)]
        for i in range(1, N+1):
            stidle.append(dist["shat"][i]**(1/self.sks[i]))
        
        w = self.group.random(ZR)
        z,a1,a2=[0 for i in range(0,len(self.sks))],[0 for i in range(0,len(self.sks))],[0 for i in range(0,len(self.sks))]
        c = self.group.hash(str(self.pks)+str(dist["shat"]), ZR)
        
        for i in range(1, len(z)):
            a1[i] = self.g**w
            a2[i] = stidle[i]**w        
            z[i] = w - self.sks[i] * c    
        
        dleqPrfs= {"c":c, "a1":a1, "a2":a2, "z":z}        
        recon=dleqPrfs.copy()
        recon["stidle"]=stidle
        print("reconstruct message size %.2fKB"%(len(str(recon))/1024.))
        
        # Check DLEQ proofs by the recover
        starttime=time.time()
        c = self.group.hash(str(self.pks)+str(dist["shat"]), ZR)
        for i in range(1, N+1):
            if recon["a1"][i] != (self.g**recon["z"][i]) * (self.pks[i]**c)\
                or recon["a2"][i] !=stidle[i]** recon["z"][i] * (dist["shat"][i] **c):
                return -1
        # print("ScrapeDDH reconstruction verification cost ",time.time()- starttime)

        indexArr = [i for i in range(1,N+1)]

        random.shuffle(indexArr)
        indexArr=indexArr[0:t]
        y = self.util.recoverCoefficients(indexArr)
        z=self.group.init(G1,1)
        for i in indexArr:    
            z *= stidle[i]**y[i]    
        print("ScrapeDDH reconstruction cost %.2fs"%(time.time()- starttime))
        return z
        
groupObj = PairingGroup(setting.curveName)
scrape = SCRAPE(groupObj)
print("N=%d,t=%d"%(N,t))
dis= scrape.distribute()
scrape.verify(dis)
assert scrape.S == scrape.reconstruct(dis)



