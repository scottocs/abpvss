from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random
import time, sys
import setting

N = setting.N
t = setting.t


class PPVSS():

    # setup()
    def __init__(self, groupObj):
        global util, group
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()

        # shareholders are in [1, N]
        self.sks = [self.group.random(ZR) for i in range(0, N + 1)]
        self.pks = [self.g ** self.sks[i] for i in range(0, N + 1)]
        self.S = self.group.random(G1)
        self.codeword = [self.group.init(ZR, 1)]
        for i in range(1, N + 1):
            vi = self.group.init(ZR, 1)
            for j in range(1, N + 1):
                if i != j:
                    vi=vi*1/(self.group.init(ZR, i)-j)  
                    # print(vi,i,j)
            self.codeword.append(vi)

    def distribute(self, j):
        ts = time.time()
        s = self.group.random(ZR)
        self.S = self.g ** s
        shares = self.util.genShares(s, t, N)
        # print(s,shares,len(shares))
        # vs = [0]
        # vs.extend([self.gp ** shares[i] for i in range(1, N + 1)])
        # print(shat)
        shat = [0]
        shat.extend([self.pks[i] ** shares[i] for i in range(1, N + 1)])

        # LDEI proofs
        r_s = self.util.genShares(0, t, N)
        # print(len(r_s),len(shares))
        ai_s = [0]
        ai_s.extend([self.pks[i] ** r_s[i] for i in range(1, N + 1)])
        e = self.group.hash(str(self.pks) + str(shat), ZR)
        z_s = [0]
        z_s.extend(e * shares[i] + r_s[i] for i in range(1, N+1))
        # print("verify:", (shat[1] ** e) * ai_s[1] == self.pks[1] ** z_s[1])
        LDEIpr = {"e": e, "ai_s": ai_s, "z_s": z_s}

        dist = LDEIpr.copy()
        dist["shat"] = shat
        # dist["vs"] = vs
        if j == 0:
            print("Albatross dis message size %.2fKB" %( len(str(dist))%1024.))
        print("Albatross distribution cost %.2fs"%(time.time()- ts))
        return dist

    def LDEI_verify(self, dist):
        starttime = time.time()
        # Check LDEI proofs
        c = self.group.hash(str(self.pks) + str(dist["shat"]), ZR)

        # Check LDEI proofs
        for i in range(1, N + 1):
            # Calculate ai_s raised to the power of c
            ai_s_c = (dist["shat"][i] ** c) * (dist["ai_s"][i])
            # Calculate g raised to the power of z_s[i]
            g_z_s = self.pks[i] ** dist["z_s"][i]
            # Check if ai_s^c equals g^z_s
            if ai_s_c != g_z_s:
                print(i)
                return {"result": False, "cost": 0}

        print("Albatross verification cost %.2fs"%(time.time() - starttime))
        # time_cost = time.time() - starttime
        # return {"result": True, "cost": time_cost}

    def local_LDEI(self,dist):
        v = self.group.init(G1, 1)
        
        for i in range(1, N + 1):
            v = v * (dist["vs"][i] ** self.codeword[i])
            # assert dist["vs"][i] ** self.codeword[i] == 0
        if v != self.group.init(G2, 1):
           return False
        return True

    def dleq_verify(self, dist):
        starttime = time.time()
            # Check DLEQ proofs
        c = self.group.hash(str(dist["vs"]) + str(dist["shat"]), ZR)
        for i in range(1, N + 1):
            if dist["a1"][i] != (self.g ** dist["z"][i]) * (self.pks[i] ** c) \
                    or dist["a2"][i] != dist["vs"][i] ** dist["z"][i] * (dist["shat"][i] ** c):
                return False
        return True



    def reconstruct(self, dist, j):

        # DLEQ proofs by shareholders
        stidle = [self.group.init(G1, 1)]
        for i in range(1, N + 1):
            stidle.append(dist["shat"][i] ** (1 / self.sks[i]))



        w = self.group.random(ZR)
        z, a1, a2 = [0 for i in range(0, len(self.sks))], [0 for i in range(0, len(self.sks))], [0 for i in range(0,
                                                                                                                  len(self.sks))]
        c = self.group.hash(str(stidle) + str(dist["shat"]), ZR)

        for i in range(1, len(z)):
            a1[i] = self.g ** w
            a2[i] = stidle[i] ** w
            z[i] = w - self.sks[i] * c

        dleqPrfs = {"c": c, "a1": a1, "a2": a2, "z": z}
        recon = dleqPrfs.copy()
        recon["vs"] = stidle
        recon["shat"] = dist["shat"]
        if j == 1:
            print("Albatross rec message size %.2fKB"% (len(str(recon))/1024.))
        starttime = time.time()
        DLEQ_verification = self.dleq_verify(recon)
        assert DLEQ_verification == True
        Locol_LDEI_verification = self.local_LDEI(recon)
        assert Locol_LDEI_verification == True
        # time_cost = time.time() - starttime
        # print("Albatross reconstruct verification cost ", time.time() - starttime)

        indexArr = [i for i in range(1, N + 1)]

        random.shuffle(indexArr)
        indexArr = indexArr[0:t]
        y = self.util.recoverCoefficients(indexArr)
        z = self.group.init(G1, 1)
        for i in indexArr:
            z *= stidle[i] ** y[i]
        if self.S != z:
            return -2
        print("Albatross reconstruction cost %.2fs"%(time.time()- starttime))                
        # return time_cost


groupObj = PairingGroup(setting.curveName)
albatross = PPVSS(groupObj)
print("N=%d,t=%d" % (N, t))
ver_cost = 0
rec_cost = 0
n=1
for i in range(n):
    dis = albatross.distribute(i)
    albatross.LDEI_verify(dis)
    # if i == 1:
    #     print("Albatross verification result: ", ver_result["result"])
    # ver_cost += ver_result["cost"]
    albatross.reconstruct(dis, i)
# print("Albatross verification cost:", ver_cost/n)



# print(result)



