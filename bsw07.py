
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random as mathrandom

# type annotations
mpk_t = { 'g':G1, 'g2':G2, 'h':G1, 'f':G1, 'e_gg_alpha':GT }
msk_t = {'beta':ZR, 'g2_alpha':G2 }
key_t = { 'D0':G2, 'D1':G2, 'D2':G1, 'S':str }
ct_t = { 'C0':GT, 'C1':G1, 'C2':G1, 'C3':G2 }


debug = False
class CPabe_BSW07(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(mpk_t, msk_t)    
    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP(); gp.initPP()
        
        h = g ** beta
        f = g ** ~beta
        f2= gp ** ~beta
        e_gg_alpha = pair(g, gp ** alpha)
        
        mpk = { 'g':g, 'g2':gp, 'h':h, 'f':f, 'f2':f2, 'e_gg_alpha':e_gg_alpha }
        msk = {'beta':beta, 'g2_alpha':gp ** alpha ,"alpha":alpha}
        return (mpk, msk)
    

    # @Input(mpk_t, msk_t, [str])
    @Output(key_t)
    def keygenAndElgamalEncAndVerify(self, mpk, msk, S, elgamalKeys):
        r = group.random() 
        g_r = (mpk['g2'] ** r)
        g_alpha=mpk['g'] ** msk['alpha']
        ED0 = mpk['f2']**(r+msk['alpha']) #(msk['g2_alpha'] * g_r) ** (1 / msk['beta'])        
        ED1, ED2 = {}, {}
        ED3={}
        attr2r_j={}
        attr2l={}
        for j in S:
            r_j = group.random()
            attr2r_j[j]=r_j
            ED1[j] = g_r * (group.hash(j, G2) ** r_j)
            # print(elgamalKeys[j]['pk'])
            l=group.random()
            attr2l[j]=l
            ED2[j]=mpk['g'] ** r_j* (elgamalKeys[j]['pk']**l)
            ED3[j]=mpk['g']**l

        rp = group.random() 
        g_rp = (mpk['g2'] ** rp)         
        alphap=group.random() 
        g_alphap=mpk['g'] ** alphap
        # betap= group.random()
        ED0p = mpk['f2']**(rp+alphap)  
        # ED0p = (alphap * g_rp) ** (1 / msk['beta'])
        ED1p, ED2p = {}, {}
        ED3p={}
        attr2r_jp={}
        attr2lp={}
        for j in S:
            r_jp = group.random()
            attr2r_jp[j]=r_jp
            ED1p[j] = g_rp * (group.hash(j, G2) ** r_jp)
            # print(elgamalKeys[j]['pk'])
            lp=group.random()
            attr2lp[j]=lp
            ED2p[j]=mpk['g'] ** r_jp* (elgamalKeys[j]['pk']**lp)
            ED3p[j]=mpk['g']**lp
        c=group.hash((ED0,ED0p,ED1p,ED1p,ED2p,ED2p,ED3p,ED3p,g_r,g_rp, g_alpha,g_alphap), ZR)
        
        alphatidle=alphap-c*msk['alpha']
        # betatidle=1/betap-c*(1/msk['beta'])
        rtidle=rp-r*c
        attr2r_jtidle={}
        attr2ltidle={}
        for j in S:
            attr2r_jtidle[j]=attr2r_jp[j]-attr2r_j[j]*c
            attr2ltidle[j]=attr2lp[j]-attr2l[j]*c

        
        assert(ED0p==mpk['f2']** (alphatidle+rtidle) *  ED0**c)
        for j in S:
            assert(ED1p[j]==mpk['g2']** rtidle * group.hash(j, G2) ** attr2r_jtidle[j] * ED1[j]**c)
            assert(ED2p[j]==mpk['g']** attr2r_jtidle[j]* (elgamalKeys[j]['pk']**attr2ltidle[j]) * ED2[j]**c)
            assert(ED3p[j]==mpk['g']** attr2ltidle[j] * ED3[j]**c)
        assert(g_rp==mpk['g2']**rtidle * g_r **c)
        assert(g_alphap==mpk['g']**alphatidle * g_alpha **c)
        return {'ED0':ED0, 'ED1':ED1, 'ED2':ED2,'ED3':ED3, 'S':S}
    
    @Input(mpk_t, GT, str)
    @Output(ct_t)
    def encryptAndVerify(self, mpk, M, policy_str):  
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        # print(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)      
        print("secret0",s)
        sp = group.random(ZR)
        sharesp = util.calculateSharesDict(sp, policy)

        C0=(mpk['e_gg_alpha'] ** s) * M
        C1 = mpk['h'] ** s
        C2, C3 = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C2[i] = mpk['g'] ** shares[i]
            C3[i] = group.hash(j, G2) ** shares[i] 
        
        Mp=group.random(GT)
        C0p=(mpk['e_gg_alpha'] ** sp) * Mp
        C1p = mpk['h'] ** sp
        C2p, C3p = {}, {}
        for i in sharesp.keys():
            j = util.strip_index(i)
            C2p[i] = mpk['g'] ** sharesp[i]
            C3p[i] = group.hash(j, G2) ** sharesp[i] 
        
        c=group.hash((C0,C0p,C1,C1p,C2,C2p,C3,C3p), ZR)
        stidle=sp-c*s
        # stidle=sp-c*s
        Mtilde = Mp/(M**c)
        sharestidle = {}
        sharestidletest=[stidle]
        for i in sharesp.keys():
            j = util.strip_index(i)
            sharestidle[i] = sharesp[i] - c * shares[i] #% curve_order
            sharestidletest.append(sharesp[i] - c * shares[i])
            # sharestidletest.append(shares[i])
        

        assert(C0p==Mtilde* mpk['e_gg_alpha']**stidle * C0**c)
        assert(C1p==mpk['h']**stidle * C1**c)
        for i in sharesp.keys():            
            j = util.strip_index(i)
            assert(C2p[i] == mpk['g']**sharestidle[i] * C2[i]**c )
            assert(C3p[i] == group.hash(j, G2)  ** sharestidle[i] * C3[i]**c)
        
        indexArr = self.tInNrandom(len(a_list)/2+1,len(a_list))
    
        y = util.recoverCoefficients(indexArr)
        z=0
        for i in indexArr:            
            z += sharestidletest[i]*y[i]
        assert(stidle==z)
        return { 'C0':C0,
                 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str, 'attributes':a_list }
    
    def tInNrandom(self, t, n) :
        arr = [];
        while True:
            if len(arr) < t:#原数组长度为0，每次成功添加一个元素后长度加1，则当数组添加最后一个数字之前长度为9即可
                num = int(mathrandom.random() * n);#生成一个0-100的随机整数
                if num not in arr:
                    arr.append(num)
            else:
                break
        return arr


    @Input(mpk_t, key_t, ct_t)
    @Output(GT)
    def decrypt(self, mpk, key, ct):
        
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, key['S'])
        # if pruned_list == False:
        #     return False
        z = util.newGetCoefficients(policy, pruned_list)
        A = 1 
        for i in pruned_list:
            j = i.getAttributeAndIndex(); k = i.getAttribute()
            A *= ( pair(ct['C2'][j], key['D1'][k]) / pair(key['D2'][k], ct['C3'][j]) ) ** z[j]
        
        return ct['C0'] / (pair(ct['C1'], key['D0']) / A)


def main():   
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_BSW07(groupObj)
    attrs = ['ONE', 'TWO', 'THREE', 'FOUR']
    # access_policy = '((four or three) and (three or one))'
    access_policy = '(2 of (ONE, TWO, THREE, FOUR))'
    if debug:
        print("Attributes =>", attrs); print("Policy =>", access_policy)

    (mpk, msk) = cpabe.setup()
    elgamalKeys={}
    for attr in attrs:
        sk=groupObj.random(ZR)
        elgamalKeys[attr]={
            "sk":sk,
            "pk":mpk['g']**sk
        }
    
    Enckey = cpabe.keygenAndElgamalEncAndVerify(mpk, msk, attrs, elgamalKeys)
    # print("Enckey :=>", Enckey)

    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encryptAndVerify(mpk, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)

    key = {
        "D0": Enckey["ED0"],
        "D1":Enckey["ED1"],
        "D2":{},
        "S":attrs
    }
    for attr in attrs:
        # key["D1"][attr]= Enckey["ED1"][attr]
        key["D2"][attr]= Enckey["ED2"][attr]/(Enckey["ED3"][attr]**elgamalKeys[attr]['sk'])
     

    rec_msg = cpabe.decrypt(mpk, key, ct)
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")

if __name__ == "__main__":
    debug = True
    main()
   