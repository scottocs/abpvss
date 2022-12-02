
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random as mathrandom
import time,sys
import setting
ret={}
keyV=1
assertExe=True


N = setting.N
t=setting.t

class DCPabe():
    def __init__(self, groupObj):
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()
        self.egg = pair(self.g, self.gp)
        # shareholders are in [1, N]

        self.sks={}
        self.pks={}
        for i in range(0,N):
            name="AUTH"+str(i)
            self.sks[name]=self.group.random(ZR)
            self.pks[name]=self.g**self.sks[name]
        self.N=N
        self.t=t
        
    def encrypt(self,M,policy_str,GID,pks,s=None,shares=None): 
        ts=time.time()
        policy = self.util.createPolicy(policy_str)
        a_list = self.util.getAttributeList(policy)
        
        if s==None:
            s = self.group.random(ZR)
            shares = self.util.calculateSharesDict(s, policy)
        
        C0=M* self.egg ** (s*self.group.hash(GID, ZR))
        C1 = {}
        for i in shares.keys():
            j = self.util.strip_index(i)
            auth=j.split("@")[1]
            C1[i] = pks[auth] ** (shares[i]*self.group.hash(i, ZR))
    
        return { 'C0':C0,'C1':C1, 'policy':policy_str}
    def keygen(self, GID, C1i, u, ski):
        # return C1i ** (self.group.hash(GID, ZR)/(ski*  self.group.hash(u, ZR)))
        return C1i ** (1/ski)

    def decrypt(self,ct, K,GID):

        policy = self.util.createPolicy(ct['policy'])
        pruned_list = self.util.prune(policy, K['S'])
        
        # print(pruned_list)
        z = self.util.newGetCoefficients(policy, pruned_list)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex();   
            attr = i.getAttribute()
            
            A *= K[attr]**(z[j] *self.group.hash(GID, ZR)/self.group.hash(attr, ZR))
        
        return ct['C0'] / pair(A, self.gp) 

if __name__ == "__main__":
# def main():   
    groupObj = PairingGroup(setting.curveName)
    #  params = {'SS512':a, 'SS1024':a1, 'MNT159':d159, 'MNT201':d201, 'MNT224':d224, 'BN254':f254 }
    # N=n
    print(N)
    cpabe = DCPabe(groupObj)
    # attrs = ['ONE', 'TWO', 'THREE', 'FOUR']
    attrs = ["ATTR%d@AUTH%d" % (j,j) for j in range(0, N)]
    # print(attrs)
    # t=int(N/3)
    access_policy = '(%d of (%s))'%(t,", ".join(attrs))
    # (2 of ((2 of (ATTR0@AUTH0,ATTR1@AUTH1,ATTR2@AUTH2)),ATTR3@AUTH3))
    # acp1='(%d of (%s))'%(6,", ".join(attrs[0:10]))
    rand_msg = groupObj.random(GT)
    GID="GID"
    st=time.time()
    ct = cpabe.encrypt(rand_msg, access_policy,GID,cpabe.pks)    
    print("DABE enc:",time.time()-st)
    print("DABE ct size:", len(str(ct))/1024)
    K={"S":[]}
    
    costtime=0   
    cnt=0
    for i in range(0,N):

        u="ATTR%d@AUTH%d" % (i,i)
        if u in ct["C1"]:
            st=time.time()     
            Ku = cpabe.keygen(GID, ct["C1"][u], u, cpabe.sks["AUTH"+str(i)])
            costtime+=time.time()-st
            cnt+=1
            K[u]=Ku
            K["S"].append(u)
    print("DABE keygen cost",costtime/cnt)
        
    # print(K)
    # print("reconstruction size:=>", "("+str(N)+","+str('%.2f' % (len(newjson.dumps(key["D2"])) *t/N/1024.))+"kB)")

    st=time.time()
    rec_msg = cpabe.decrypt(ct,K,GID)
    print("DABE dec:",time.time()-st)
    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    # if debug: print("Successful Decryption!!!")

# if __name__ == "__main__":
#     debug = True
#     # assertExe===0? False :True
#     asser=lambda x: x if x=="True" else False 
#     # assertExe=asser(sys.argv[1])    
#     runtimes=1
#     Nmax=20
#     for n in range(10, Nmax, 10):        
#         print("n=",n)
#         ret[n]={"dis":0,"ver":0,"rec":0}
#         ts=time.time()           
#         keyV=n
#         for i in range(0, runtimes):
#             main()
#         # print("("+str(n)+", "+ str('%.2f' % (ret[n]["dis"]*1./runtimes))+") ")
#     # print(ret)
#     dis=""
#     ver=""
#     rec=""
#     # print the time cost for each phase
#     for n in range(10, Nmax, 10):        
#         dis+="("+str(n)+", "+ str('%.2fs' % (ret[n]["dis"]*1./runtimes))+") "
#         ver+="("+str(n)+", "+ str('%.2fs' % (ret[n]["ver"]*1./runtimes))+") "
#         rec+="("+str(n)+", "+ str('%.2fs' % (ret[n]["rec"]*1./runtimes))+") "
#     print("")
#     print("distribution time cost:",dis)
#     print("verification time cost:",ver)
#     print("reconstruction time cost:",rec)
    
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


   