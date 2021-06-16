'''
Lewko-Waters Decentralized Attribute-Based Encryption

| Lewko, Allison, and Brent Waters, "Decentralizing Attribute-Based Encryption.", Appendix D
| Published in: Eurocrypt 2011
| Available from: http://eprint.iacr.org/2010/351.pdf

* type:           encryption (identity-based)
* setting:        bilinear groups (asymmetric)

:Authors:    Gary Belvin
:Date:           06/2011
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

# from charm.toolbox.pairinggroup import *
from newsecretutils import Utils
import re
import time

debug = False


class Dabe(ABEncMultiAuth):
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
        # util = SecretUtil(groupObj, verbose=False)  # Create Secret Sharing Scheme
        util = Utils(groupObj, verbose=False)  # Create Secret Sharing Scheme
        group = groupObj  #:Prime order group

    # Another comment

    def setup(self):
        '''Global Setup'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G

        #:group contains
        #:the prime order p is contained somewhere within the group object
        g1 = group.random(G1)
        g2 = group.random(G2)
        #: The oracle that maps global identities GID onto elements of G
        #:H = lambda str: g** group.hash(str)
        H = lambda x: group.hash(x, G1)
        GP = {'g1': g1, 'g2': g2, 'H': H}

        return GP

    def authsetup(self, GP, attributes):
        '''Authority Setup for a given set of attributes'''
        # For each attribute i belonging to the authority, the authority chooses two random exponents,
        # alpha_i, y_i and publishes PK={e(g,g)^alpha_i, g^y_i} for each attribute
        # it keeps SK = {alpha_i, y_i} as its secret key
        SK = {}  # dictionary of {s: {alpha_i, y_i}}
        PK = {}  # dictionary of {s: {e(g,g)^alpha_i, g^y}}
        for i in attributes:
            # TODO: Is ZR an appropriate choice for a random element in Zp?
            alpha_i, y_i = group.random(), group.random()
            e_gg_alpha_i = pair(GP['g1'], GP['g2']) ** alpha_i
            g_y_i = GP['g2'] ** y_i
            SK[i.upper()] = {'alpha_i': alpha_i, 'y_i': y_i}
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^y_i': g_y_i}

        if (debug):
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
        # To create a key for GID for attribute i belonging to an authority, the authority computes K_{i,GID} = g^alpha_i * H(GID)^y_
        h = gp['H'](gid)
        K = (gp['g1'] ** sk[i.upper()]['alpha_i']) * (h ** sk[i.upper()]['y_i'])

        pkey[i.upper()] = {'k': K}
        pkey['gid'] = gid

        if (debug):
            print("Key gen for %s on %s" % (gid, i))
            print("H(GID): '%s'" % h)
            print("K = g^alpha_i * H(GID) ^ y_i: %s" % K)
        return None

    def encrypt(self, gp, pk, M, policy_str):
        '''Encrypt'''
        # M is a group element
        # pk is a dictionary with all the attributes of all authorities put together.
        # This is legal because no attribute can be shared by more than one authority
        # {i: {'e(gg)^alpha_i: , 'g^y_i'}
        s = group.random()
        w = group.init(ZR, 0)
        egg_s = pair(gp['g1'], gp['g2']) ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}

        # Parse the policy string into a tree
        policy = util.createPolicy(policy_str)

        sshares = util.calculateSharesList(s, policy)  # Shares of the secret
        print('sshares', sshares)
        wshares = util.calculateSharesList(w, policy)  # Shares of 0

        wshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in wshares])
        sshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in sshares])
        for attr, s_share in sshares.items():
            k_attr = util.strip_index(attr)
            w_share = wshares[attr]
            r_x = group.random()
            C1[attr] = (pair(gp['g1'], gp['g2']) ** s_share) * (pk[k_attr]['e(gg)^alpha_i'] ** r_x)
            C2[attr] = gp['g2'] ** r_x
            C3[attr] = (pk[k_attr]['g^y_i'] ** r_x) * (gp['g2'] ** w_share)

        return {'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'policy': policy_str}

    def divideCT(self, ct1, ct2):
        policy_str = ct1['policy']
        if ct1['policy'] != ct2['policy']:
            print("policy not equal!! cannot divide")
            return
        C0 = ct1['C0'] / ct2['C0']
        policy = util.createPolicy(policy_str)
        attribute_list = util.getAttributeList(policy)

        C1, C2, C3= {}, {}, {}
        for i in attribute_list:
            C1[i] = ct1['C1'][i] / ct2['C1'][i]
            C2[i] = ct1['C2'][i] / ct2['C2'][i]
            C3[i] = ct1['C3'][i] / ct2['C3'][i]
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3}

    def decrypt(self, gp, sk, ct):
        '''Decrypt a ciphertext
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        '''
        usr_attribs = list(sk.keys())
        usr_attribs.remove('gid')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")
        coeffs = util.newGetCoefficients(policy,pruned)

        h_gid = gp['H'](sk['gid'])  # find H(GID)
        egg_s = 1
        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            num = ct['C1'][x] * pair(h_gid, ct['C3'][x])
            dem = pair(sk[y]['k'], ct['C2'][x])
            egg_s *= ((num / dem) ** coeffs[x])

        if (debug): print("e(gg)^s: %s" % egg_s)

        return ct['C0'] / egg_s


def main():
    groupObj = PairingGroup('SS512')

    dabe = Dabe(groupObj)
    GP = dabe.setup()

    # Setup an authority
    auth_attrs = ['ONE', 'TWO', 'THREE', 'FOUR']
    (SK, PK) = dabe.authsetup(GP, auth_attrs)
    if debug: print("Authority SK")
    if debug: print(SK)

    # Setup an authority
    auth_attrs2 = ['FIVE']
    (SK2, PK2) = dabe.authsetup(GP, auth_attrs2)


    # Setup a user and give him some keys
    gid, K = "bob", {}
    usr_attrs = ['THREE', 'ONE', 'TWO','FIVE']
    for i in usr_attrs:
        if i.upper() in auth_attrs:
            dabe.keygen(GP, SK, i, gid, K)
        if i.upper() in auth_attrs2:
            dabe.keygen(GP, SK2, i, gid, K)

    if debug: print('User credential list: %s' % usr_attrs)
    if debug: print("\nSecret key:")
    if debug: groupObj.debug(K)

    # Encrypt a random element in GT
    m = groupObj.random(GT)
    m2 = groupObj.random(GT)
    policy = '(2 of (ONE, TWO, THREE,five))'
    # policy='one or two'
    if debug: print('Acces Policy: %s' % policy)
    # print(PK)
    # print(PK2)
    # print(Merge(PK,PK2))

    CT = dabe.encrypt(GP, Merge(PK,PK2), m, policy)
    CT2 = dabe.encrypt(GP, Merge(PK,PK2), m2, policy)

    t1 = time.time()
    orig_m1 = dabe.decrypt(GP, K, CT)
    orig_m2 = dabe.decrypt(GP, K, CT2)
    t2 = time.time()
    print("2 decryption: t2-t1", t2-t1)
    t1 = time.time()
    CT3 = dabe.divideCT(CT, CT2)
    # if debug: print("\nCiphertext...")
    # if debug: groupObj.debug(CT)
    orig_m3 = dabe.decrypt(GP, K, CT3)
    t2 = time.time()
    print("homomorphic decryption: t2-t1", t2 - t1)
    assert m/m2 == orig_m3, 'FAILED Decryption!!!'
    if debug: print('Successful Decryption!')



def Merge(dict1, dict2):
    res = {**dict1, **dict2}
    return res

if __name__ == '__main__':
    debug = False
    main()
