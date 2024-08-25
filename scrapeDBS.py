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
    def __init__(self, groupObj):        
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()
        
        # shareholders are in [1, N]
        self.sks=[self.group.random(ZR) for i in range(0,N+1)]
        self.pks=[self.gp**self.sks[i] for i in range(0,N+1)]
        # self.ppks=[self.g**self.sks[i] for i in range(0,N+1)]
        self.codeword=[self.group.init(ZR,1)]
        for i in range(1, N+1):            
            vi = self.group.init(ZR,1)
            for j in range(1,N+1):
                if i!=j:
                    vi=vi*1/(self.group.init(ZR, i)-j)  
                    # print(vi,i,j)
            self.codeword.append(vi)
        # pre-compute the coefficients
        # self.util.recoverCoefficients([i for i in range(1, self.cpabe.N+1)])
           
    def distribute(self):
        ts=time.time()
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
        
        print("distribute message size %.2fKB"%(len(str(res))/1024))
        print(f"ScrapeDBS distribution cost %.2fs"%(time.time()- ts))     
        return res


    def verify(self, dis):
        starttime = time.time()
        
        for i in range(1, N+1):
            if pair(self.g,dis["shat"][i]) != pair(dis["vs"][i],self.pks[i]):                
                return -1
            if setting.curveName not in ["SS512"]:
                # if pair(self.g,self.pks[i]) != pair(self.ppks[i], self.gp):
                if pair(self.g,self.pks[i]) != pair(self.pks[i], self.gp):
                    return -2

            

        # reed solomon check        
        v=self.group.init(G1,1)        
        for i in range(1, N+1):
            v=v * (dis["vs"][i]**self.codeword[i])
        assert v == self.group.init(G1,1)
        print(f"SCRAPE DBS verification cost %.2fs"%(time.time()- starttime))
        return True

    def reconstruct(self,dis):
        # g^s sent by shareholders
        stidle=[self.group.init(G2,1)]
        for i in range(1, N+1):
            stidle.append(dis["shat"][i]**(1/self.sks[i]))
        
        recon={}
        recon["stidle"]=stidle
        print(f"reconstruct message size %.2fKB"%(len(str(recon))/1024.))
        
        # Check Pairing by the recover
        starttime=time.time()
        for i in range(1, N+1):
            # if pair(self.ppks[i], stidle[i]) != pair(self.g, dis["shat"][i]):
            if pair(self.pks[i], stidle[i]) != pair(self.gp, dis["shat"][i]):
                return -1
        
        indexArr = [i for i in range(1,N+1)]

        random.shuffle(indexArr)
        indexArr=indexArr[0:t]        
        y = self.util.recoverCoefficients(indexArr)
        z=self.group.init(G2,1)
        for i in indexArr:    
            z *= stidle[i]**y[i]    
        print(f"SCRAPE DBS reconstruction cost %.2fs"%(time.time()- starttime))
        if self.S!=z: 
            return -2
        return z

groupObj = PairingGroup(setting.curveName)
scrape = SCRAPE(groupObj)
print("N=%d,t=%d"%(N,t))
dis= scrape.distribute()
# print(scrape.verify(dis["shat"], dis["vs"]))
scrape.verify(dis)
scrape.reconstruct(dis)


