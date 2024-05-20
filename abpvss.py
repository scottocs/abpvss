 
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
        access_policy = '(%d of ('%int(part/2);
        for i in range(0, part):
            piece="(%d of (%s))"%(partAttrNums, ", ".join(attrs[i*partAttrNums:partAttrNums*(i+1)]))
            access_policy += piece+","
        
        access_policy=access_policy[:-1]+"))"

        # access_policy = '(%d of (%s))'%(self.cpabe.t,", ".join(attrs))
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
        # print("GT",len(str(self.group.random(GT))))
        # print("G1",len(str(self.group.random(G1))))
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
        print("ABPVSS distribution cost:",time.time()- ts)     
        return {"C":C,"proofs":proofs}

    def verify(self, C, proofs):
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
        print("ABPVSS verification cost:",time.time()- ts)                

        
        return True

    def checkKey(self,C, K,GID):
        
        for u in K:
            if u!="S":
                auth =u.split("@")[1].split("_")[0]
                if pair(C["C1"][u],self.cpabe.g) != \
                    pair(self.cpabe.pks[auth],K[u]):
                    return False
            
        return True
      
    def genProofs2(self,C, K,GID):    

        w = self.group.random(ZR)
        z,a1,a2={},{},{}
        c = self.group.hash(str(C)+str(self.cpabe.pks), ZR)
        
        for u in K:
            if u!="S":
                
                auth =u.split("@")[1]
                a1[u] = K[u]**w
                a2[u] = self.cpabe.g**w        
                z[u] = w - self.cpabe.sks[auth] * c    

        dleqPrfs= {"c":c, "a1":a1, "a2":a2, "z":z}
        return dleqPrfs

    def checkKey2(self, C, K, GID,dleqPrfs):
        c = self.group.hash(str(C)+str(self.cpabe.pks), ZR)
        for u in K:
            if u!="S":
                auth =u.split("@")[1]
                # Cp= C["C1"][u]**(self.group.hash(GID, ZR)/self.group.hash(u, ZR))
                if dleqPrfs["a1"][u] != (K[u]**dleqPrfs["z"][u]) * ( C["C1"][u]**c) \
                  or dleqPrfs["a2"][u] !=self.cpabe.g** dleqPrfs["z"][u] * (self.cpabe.pks[auth] **c):
                    return False
        return True

    def reconstruct(self, C, proofs,rand_msg):
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
        print("rec message size:",len(str(recon)))        

        # checkKey
        ts=time.time()
        if not self.checkKey(C, K, GID):
            return -1
        # print("ABPVSS reconstruct verification1 ","cost:",time.time()- ts)                
        

        # ts=time.time()
        # dleqPrfs=self.genProofs2(C,K, GID)
        # recon={}
        # recon.update(K)
        # recon.update(dleqPrfs)
        # print("rec message size:",len(str(recon)))        
        # if not self.checkKey2(C,K,GID,dleqPrfs):
        #     return -1
        # print("ABPVSS reconstruct verification2 cost","cost:",time.time()- ts)                
        # ts=time.time()                
        rec_msg = self.cpabe.decrypt(C,K,GID)
        if rand_msg != rec_msg:
            return -2
        print("ABPVSS reconstruct decryption ","cost:",time.time()- ts)                
        
        return True
    



def main():   
    groupObj = PairingGroup(setting.curveName)
    #  params = {'SS512':a, 'SS1024':a1, 'MNT159':d159, 'MNT201':d201, 'MNT224':d224, 'BN254':f254 }
    # N=n
    
    abpvss = ABPVSS(groupObj)
    print("N=%d,t=%d"%(abpvss.cpabe.N,abpvss.cpabe.t))
    # attrs = ['ONE', 'TWO', 'THREE', 'FOUR']
    # attrs = ["ATTR%d@AUTH%d" % (j,j) for j in range(0, abpvss.cpabe.N)]
    # print(attrs)
    # t=int(N/3)
    # access_policy = '(%d of (%s))'%(abpvss.cpabe.t,", ".join(attrs))
    # (2 of ((2 of (ATTR0@AUTH0,ATTR1@AUTH1,ATTR2@AUTH2)),ATTR3@AUTH3))
    # acp1='(%d of (%s))'%(6,", ".join(attrs[0:10]))
    # acp2='(%d of (%s))'%(6,", ".join(attrs[10:20]))
    # # acp2='(%d of (%s))'%(6,", ".join(attrs[10:20]))
    # access_policy = '(2 of ((%s), (%s)))'%(acp1,acp2)
    

    rand_msg = groupObj.random(GT)
    GID="GID"
    trans = abpvss.distribute(GID,rand_msg)    
    print("dis message size:",len(str(trans)))
    abpvss.verify(trans["C"], trans["proofs"])
    print(abpvss.reconstruct(trans["C"], trans["proofs"],rand_msg))
    # K={"S":[]}
    # for i in range(0,N):
    #     u="ATTR%d@AUTH%d" % (i,i)
    #     if u in ct["C1"]:
    #         Ku = abpvss.keygen(GID, ct["C1"][u], u, abpvss.sks["AUTH"+str(i)])
    #         K[u]=Ku
    #         K["S"].append(u)
    # print(K)
    # # print("reconstruction size:=>", "("+str(N)+","+str('%.2f' % (len(newjson.dumps(key["D2"])) *t/N/1024.))+"kB)")

    # rec_msg = abpvss.decrypt(ct,K)
    # assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    # # if debug: print("Successful Decryption!!!")

if __name__ == "__main__":
    debug = True
    runtimes=1
    Nmax=20
    for n in range(10, Nmax, 10):        
        # print("n=",n)
        ret[n]={"dis":0,"ver":0,"rec":0}
        ts=time.time()           
        keyV=n
        for i in range(0, runtimes):
            main()
        # print("("+str(n)+", "+ str('%.2f' % (ret[n]["dis"]*1./runtimes))+") ")
    # print(ret)
    dis=""
    ver=""
    rec=""
    # print the time cost for each phase
    for n in range(10, Nmax, 10):        
        dis+="("+str(n)+", "+ str('%.2fs' % (ret[n]["dis"]*1./runtimes))+") "
        ver+="("+str(n)+", "+ str('%.2fs' % (ret[n]["ver"]*1./runtimes))+") "
        rec+="("+str(n)+", "+ str('%.2fs' % (ret[n]["rec"]*1./runtimes))+") "
    # print("")
    # print("distribution time cost:",dis)
    # print("verification time cost:",ver)
    # print("reconstruction time cost:",rec)
    
# increasing t
    # runtimes=4
    # n=4
    
    # # for n in range(10, 100, 10):        
    # for t in range(1,int(n/2), 5):
    #     print(t)        
    #     ts=time.time()     
    #     ret[t]={"dis":0,"ver":0,"rec":0}      
    #     keyV=t
    #     for i in range(0, runtimes):
    #         main(n,t)
    #     # print("("+str(n)+", "+ str('%.2f' % (ret[n]["dis"]*1./runtimes))+") ")
    # # print(ret)
    # rec=""
    # for t in range(1, int(n/2), 5):        
    #     # dis+="("+str(n)+", "+ str('%.2f' % (ret[t]["dis"]*1./runtimes))+") "
    #     # ver+="("+str(n)+", "+ str('%.2f' % (ret[t]["ver"]*1./runtimes))+") "
    #     rec+="("+str(t)+", "+ str('%.4f' % (ret[t]["rec"]*1./runtimes))+") "
    # print(rec)


   