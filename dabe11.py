'''
Lewko-Waters Decentralized Attribute-Based Encryption 
'''

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import SecretUtil
import utils.newjson as newjson

from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import setting
import time

N = setting.N
t=setting.t


debug = False
class Dabe():
    """
    Decentralized Attribute-Based Encryption by Lewko and Waters

    >>> group = PairingGroup('SS512')
    >>> dabe = Dabe(group)
    >>> public_parameters = dabe.setup()
    >>> auth_attrs= ['ONE', 'TWO', 'THREE', 'FOUR'] #setup an authority
    >>> (master_secret_key, master_public_key) = dabe.authsetup(public_parameters, auth_attrs)

        Setup a user and give him some keys
    >>> ID, secret_keys = "bob", {}
    >>> usr_attrs = ['THREE', 'ONE', 'TWO']
    >>> for i in usr_attrs:  dabe.keygen(public_parameters, master_secret_key, i, ID, secret_keys)
    >>> msg = group.random(GT)
    >>> policy = '((one or three) and (TWO or FOUR))'
    >>> cipher_text = dabe.encrypt(public_parameters, master_public_key, msg, policy)
    >>> decrypted_msg = dabe.decrypt(public_parameters, secret_keys, cipher_text)
    >>> decrypted_msg == msg
    True
    """
    def __init__(self, groupObj):
        ABEncMultiAuth.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)  #Create Secret Sharing Scheme
        group = groupObj    #:Prime order group        
	#Another comment
   
    def setup(self):
        '''Global Setup'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G
    
        #:group contains 
        #:the prime order p is contained somewhere within the group object
        g = group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        #:H = lambda str: g** group.hash(str)
        H = lambda x: group.hash(x, G1)
        GP = {'g':g, 'H': H}

        return GP

    def authsetup(self, GP, attributes):
        '''Authority Setup for a given set of attributes'''
        #For each attribute i belonging to the authority, the authority chooses two random exponents, 
        #alpha_i, y_i and publishes PK={e(g,g)^alpha_i, g^y_i} for each attribute 
        #it keeps SK = {alpha_i, y_i} as its secret key
        SK = {} #dictionary of {s: {alpha_i, y_i}} 
        PK = {} #dictionary of {s: {e(g,g)^alpha_i, g^y}}
        for i in attributes:
            #TODO: Is ZR an appropriate choice for a random element in Zp?
            alpha_i, y_i = group.random(), group.random()
            e_gg_alpha_i = pair(GP['g'],GP['g']) ** alpha_i
            g_y_i = GP['g'] ** y_i
            SK[i.upper()] = {'alpha_i': alpha_i, 'y_i': y_i}
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^y_i': g_y_i}
        
        if(debug):
            print("Authority Setup for %s" % attributes)
            print("SK = {alpha_i, y_i}")
            print(SK)
            print("PK = {e(g,g) ^ alpha_i, g ^ y_i}")
            print(PK)
             
        return (SK, PK)
        
    def keygen(self, gp, sk, i, gid, pkey):
        '''Create a key for GID on attribute i belonging to authority sk
        sk is the private key for the releveant authority
        i is the attribute to give bob
        pkey is bob's private key dictionary, to which the appropriate private key is added
        '''
        #To create a key for GID for attribute i belonging to an authority, the authority computes K_{i,GID} = g^alpha_i * H(GID)^y_
        h = gp['H'](gid) 
        K = (gp['g'] ** sk[i.upper()]['alpha_i']) * (h ** sk[i.upper()]['y_i'])
        
        pkey[i.upper()] = {'k': K}
        pkey['gid'] = gid
        
        if(debug):
            print("Key gen for %s on %s" % (gid, i))
            print("H(GID): '%s'" % h)
            print("K = g^alpha_i * H(GID) ^ y_i: %s" % K)
        return None

    def encrypt(self, gp, pk, M, policy_str):
        '''Encrypt'''
        #M is a group element
        #pk is a dictionary with all the attributes of all authorities put together.
        #This is legal because no attribute can be shared by more than one authority
        #{i: {'e(gg)^alpha_i: , 'g^y_i'}
        s = group.random()
        w = group.init(ZR, 0)
        egg_s = pair(gp['g'],gp['g']) ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}
        
        #Parse the policy string into a tree
        policy = util.createPolicy(policy_str)
        attr_list = util.getAttributeList(policy)
        attribute_list = util.getAttributeList(policy)
        sshares = util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        wshares = util.calculateSharesDict(w, policy)  
        # policy = util.createPolicy(policy_str)
        # sshares = util.calculateSharesList(s, policy) #Shares of the secret 
        # wshares = util.calculateSharesList(w, policy) #Shares of 0
        
    
        # wshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in wshares])
        # sshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in sshares])
        for attr, s_share in sshares.items():
            k_attr = util.strip_index(attr)
            w_share = wshares[attr]
            r_x = group.random()
            C1[attr] = (pair(gp['g'],gp['g']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r_x)
            C2[attr] = gp['g'] ** r_x
            C3[attr] = (pk[k_attr]['g^y_i'] ** r_x) * (gp['g'] ** w_share)
          
        return { 'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3, 'policy':policy_str }

    def decrypt(self, gp, sk, ct):
        '''Decrypt a ciphertext
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        ''' 
        #         policy = self.abeutils.createPolicy(ct['policy'])
        # # coefficients = self.abeutils.newGetCoefficients(policy)
        # pruned_list = self.abeutils.prune(policy, sk['keys'].keys())
        # coefficients = self.abeutils.newGetCoefficients(policy, pruned_list)

        usr_attribs = list(sk.keys())
        usr_attribs.remove('gid')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")        
        coeffs = util.newGetCoefficients(policy,pruned)
    
        h_gid = gp['H'](sk['gid'])  #find H(GID)
        egg_s = 1
        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            num = ct['C1'][x] * pair(h_gid, ct['C3'][x])
            dem = pair(sk[y]['k'], ct['C2'][x])
            egg_s *= ( (num / dem) ** coeffs[x] )
   
        if(debug): print("e(gg)^s: %s" % egg_s)

        return ct['C0'] / egg_s

if __name__ == '__main__':
    groupObj = PairingGroup('SS512')

    dabe = Dabe(groupObj)
    GP = dabe.setup()

    #Setup an authority
    # auth_attrs= ['ONE', 'TWO', 'THREE', 'FOUR']
    auth_attrs = ["ATTR%d@AUTH%d" % (j,j) for j in range(0, N)]
    (SK, PK) = dabe.authsetup(GP, auth_attrs)
    

    #Setup a user and give him some keys
    gid, K = "bob", {}
    usr_attrs = auth_attrs#['THREE', 'ONE', 'TWO']
    st=time.time()
    for i in usr_attrs: 
        dabe.keygen(GP, SK, i, gid, K)
    print("DABE11 keygen cost",(time.time()-st)/len(usr_attrs))
    # print('User credential list: %s' % usr_attrs)
    if debug: print("\nSecret key:")
    if debug: groupObj.debug(K)

    #Encrypt a random element in GT
    m = groupObj.random(GT)
    # policy = '((one or three) and (TWO or FOUR))'
    policy = '(%d of (%s))'%(t,", ".join(usr_attrs))
    # print('Acces Policy: %s' % policy)
    st=time.time()
    CT = dabe.encrypt(GP, PK, m, policy)
    print("DABE11 enc:",time.time()-st)
    print("DABE11 ct size:", len(str(CT))/1024)
    if debug: print("\nCiphertext...")
    # print(CT)

    st=time.time()
    orig_m = dabe.decrypt(GP, K, CT)
    print("DABE11 dec:",time.time()-st)
    assert m == orig_m, 'FAILED Decryption!!!'
    if debug: print('Successful Decryption!')

