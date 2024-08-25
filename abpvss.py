 
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random
import time,sys
import dabe
import setting
ret={}
keyV=1
assertExe=True



class ABPVSS():
    def __init__(self, groupObj):
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj        
        self.cpabe = dabe.DCPabe(self.group)
        
           
    def distribute(self,GID,M=None): 
        
        attrs = ["ATTR%d@AUTH%d" % (j,j) for j in range(0, self.cpabe.N)]
        part=int(sys.argv[1])
        partAttrNums=int(self.cpabe.N/part)
        # 
        # access_policy = '(%d of ('%int(part/2);
        # for i in range(0, part):
        #     piece="(%d of (%s))"%(partAttrNums, ", ".join(attrs[i*partAttrNums:partAttrNums*(i+1)]))
        #     access_policy += piece+","
        
        # access_policy=access_policy[:-1]+"))"
        access_policy = '(%d of (%s))'%(self.cpabe.t,", ".join(attrs))
        # access_policy = '(2 of ((%d of (%s)), (%d of (%s))))'%(half,", ".join(attrs[:half]),half,", ".join(attrs[half:]))
        # access_policy = '(1 of ((%d of (%s)), (%d of (%s))))'%(partAttrNums,", ".join(attrs[:partAttrNums]),partAttrNums,", ".join(attrs[partAttrNums:]))

        # print(access_policy)
        # (2 of ((2 of (ATTR0@AUTH0,ATTR1@AUTH1,ATTR2@AUTH2)),ATTR3@AUTH3))
        # acp1='(%d of (%s))'%(6,", ".join(attrs[0:10]))
        # acp2='(%d of (%s))'%(6,", ".join(attrs[10:20]))
        # acp2='(%d of (%s))'%(6,", ".join(attrs[10:20]))
        # access_policy = '(2 of ((%s), (%s)))'%(acp1,acp2)
        ts=time.time()
        if M==None:
            M = self.group.random(GT)        
        s = self.group.random(ZR)        
        acpM=self.util.createPolicy(access_policy)
        shares = self.util.calculateSharesDict(s, acpM)
        C = self.cpabe.encrypt(M, access_policy,GID,self.cpabe.pks,s,shares)    

        Mp = self.group.random(GT)
        sp = self.group.random(ZR)        
        sharesp = self.util.calculateSharesDict(sp, acpM)
        Cp = self.cpabe.encrypt(Mp, access_policy,GID,self.cpabe.pks,sp,sharesp)    


        c = self.group.hash(str(C)+str(Cp), ZR)
        Mhat=Mp/(M**c)
        shat=sp- s*c
        shareshat={}
        for attr in shares:
            shareshat[attr]=sharesp[attr] - shares[attr]*c
        proofs={"Cp":Cp,"c":c,"Mhat":Mhat,"shat":shat,"shareshat":shareshat,"GID":GID}
        print("ABPVSS distribution cost %.2fs"%(time.time()- ts))
        return {"C":C,"proofs":proofs}

    def verify(self, C, proofs):
        ts=time.time()
        # The coefficient can be performed before verification
        policy = self.util.createPolicy(C['policy'])
        # attrs = ["ATTR%d@AUTH%d" % (j,j) for j in range(0, self.cpabe.N)]
        # random.shuffle(attrs)        
        coeffs = self.util.getCoefficients(policy)        
        attrs =[k for k in coeffs]
        # print(attrs)

        ts=time.time()
        Cp=proofs["Cp"]
        shat=proofs["shat"]        
        GID=proofs["GID"]
        Mhat=proofs["Mhat"]
        shareshat=proofs["shareshat"]
        c = self.group.hash(str(C)+str(Cp), ZR)
        if Cp["C0"]!=Mhat* (self.cpabe.egg ** (shat*self.group.hash(GID, ZR))) * (C["C0"]**c):
            return False
        for attr in shareshat:
            
            # auth =attr.split("@")[1]
            auth =attr.split("@")[1].split("_")[0]
            # print(self.cpabe.pks[auth])
            # print(auth,attr)
            if Cp["C1"][attr]!= self.cpabe.pks[auth]**(shareshat[attr]*self.group.hash(attr, ZR)) * (C["C1"][attr] ** c):
                return False
                
        z=0
        for attr in attrs:
            z += shareshat[attr]*coeffs[attr]
        if z!=shat:
            return False
        print("ABPVSS verification cost %.2fs"%(time.time()- ts))

        
        return True

    def checkKey(self,C, K,GID):        
        for u in K:
            if u!="S":
                auth =u.split("@")[1].split("_")[0]
                if pair(C["C1"][u],self.cpabe.g) != pair(self.cpabe.pks[auth],K[u]):
                    return False
            
        return True
          
    def reconstruct(self, C, proofs):
        GID=proofs["GID"]
        shareshat=proofs["shareshat"]
        attrs=[k for k in shareshat]
        # print(attrs)
        # random.shuffle(attrs)        
        K={"S":[]}
        for i in range(0,self.cpabe.N):
            # attr="ATTR%d@AUTH%d" % (i,i)
            attr=attrs[i]            
            auth =attr.split("@")[1].split("_")[0]
            Ku=self.cpabe.keygen(GID, C["C1"][attr], attr, self.cpabe.sks[auth])            
            K[attr]=Ku
            K["S"].append(attr)
        
        recon=K

        print("reconstruct message size %.2fKB"%(len(str(recon))/1204.))

        ts=time.time()
        if not self.checkKey(C, K, GID):
            return -1
        decMsg = self.cpabe.decrypt(C,K,GID)
        print("ABPVSS reconstruct cost %.2fs"%(time.time()- ts))
        return decMsg
        
    

if __name__ == "__main__":
    groupObj = PairingGroup(setting.curveName)
    
    abpvss = ABPVSS(groupObj)
    print("N=%d,t=%d"%(abpvss.cpabe.N,abpvss.cpabe.t))
    rand_msg = groupObj.random(GT)
    GID="GID"
    trans = abpvss.distribute(GID,rand_msg)    
    print("distribute message size %.2fKB"%(len(str(trans))/1024.))
    abpvss.verify(trans["C"], trans["proofs"])
    assert rand_msg == abpvss.reconstruct(trans["C"], trans["proofs"])
    


   