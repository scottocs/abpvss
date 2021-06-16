# coding=utf-8

from charm.toolbox.pairinggroup import *
from newsecretutils import Utils
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import re
# from newjson import ElementEncoder, ElementDecoder
import newjson
import queue

debug = False


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def merge_dicts2(dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


class MaabeRW15(ABEncMultiAuth):

    def __init__(self, group, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = group
        self.util = Utils(group, verbose)

    def setup(self):
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        egg = pair(g1, g2)
        H = lambda x: self.group.hash(x, G2)
        F = lambda x: self.group.hash(x, G2)
        gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F}
        if debug:
            print("Setup")
            print(gp)
        return gp

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = MaabeRW15(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        alpha, y = self.group.random(), self.group.random()
        egga = gp['egg'] ** alpha
        gy = gp['g1'] ** y
        pk = {'name': name, 'egga': egga, 'gy': gy}
        sk = {'name': name, 'alpha': alpha, 'y': y}
        if debug:
            print("Authsetup: %s" % name)
            print(pk)
            print(sk)

        return pk, sk

    def keygen(self, gp, sk, gid, attribute):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        t = self.group.random()
        K = gp['g2'] ** sk['alpha'] * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
        KP = gp['g1'] ** t
        if debug:
            print("Keygen")
            print("User: %s, Attribute: %s" % (gid, attribute))
            print({'K': K, 'KP': KP})
        return {'K': K, 'KP': KP}

    def multiple_attributes_keygen(self, gp, sk, gid, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        uk = {}
        for attribute in attributes:
            uk[attribute] = self.keygen(gp, sk, gid, attribute)
        return uk

    def encrypt(self, gp, pks, message, policy_str):
        """
        Encrypt a message under an access policy
        :param gp: The global parameters.
        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
        :param message: The message to encrypt.
        :param policy_str: The access policy to use.
        :return: The encrypted message.
        """
        s = self.group.random()  # secret to be shared
        w = self.group.init(ZR, 0)  # 0 to be shared

        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)

        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)

        C0 = message * (gp['egg'] ** s)
        C1, C2, C3, C4 = {}, {}, {}, {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            tx = self.group.random()
            # print(i,pks[auth])
            # print(gp['egg'])
            # print(i, type(secret_shares) )
            # print(i, type(pks))
            # print(i, type(pks[auth]))

            C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** tx
            C2[i] = gp['g1'] ** (-tx)
            C3[i] = pks[auth]['gy'] ** tx * gp['g1'] ** zero_shares[i]
            C4[i] = gp['F'](attr) ** tx
        if debug:
            print("Encrypt")
            print(message)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4})
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}
    def divideCT(self, ct1, ct2):
        ct={}
        policy_str=ct1['policy']
        if ct1['policy'] != ct2['policy']:
            print("policy not equal!! cannot divide")
            return
        C0 = ct1['C0']/ct2['C0']
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)


        C1, C2, C3, C4 = {}, {}, {}, {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            C1[i] = ct1['C1'][i]/ct2['C1'][i]
            C2[i] = ct1['C2'][i]/ct2['C2'][i]
            C3[i] = ct1['C3'][i]/ct2['C3'][i]
            C4[i] = ct1['C4'][i]/ct2['C4'][i]
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

    def decrypt(self, gp, sk, ct):
        """
        Decrypt the ciphertext using the secret keys of the user.
        :param gp: The global parameters.
        :param sk: The secret keys of the user.
        :param ct: The ciphertext to decrypt.
        :return: The decrypted message.
        :raise Exception: When the access policy can not be satisfied with the user's attributes.
        """
        policy = self.util.createPolicy(ct['policy'])
        # coefficients = self.util.newGetCoefficients(policy)
        pruned_list = self.util.prune(policy, sk['keys'].keys())
        coefficients = self.util.newGetCoefficients(policy, pruned_list)

        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B = self.group.init(GT, 1)
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            B *= (ct['C1'][y] * pair(ct['C2'][y], sk['keys'][x]['K']) * pair(ct['C3'][y], gp['H'](sk['GID'])) * pair(
                sk['keys'][x]['KP'], ct['C4'][y])) ** coefficients[y]
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk)
            print("Decrypted Message:")
            print(ct['C0'] / B)
        return ct['C0'] / B

public_parameters = {}

CTnum = 0
result = 0
class Interface2:
    def __init__(self, nodeId):
        global public_parameters
        if not public_parameters:
            group = PairingGroup('SS512')
            maabe = MaabeRW15(group)
            public_parameters = maabe.setup()  # 初始化global setup，返回全局公共参数public_parameters

        self.group = PairingGroup('SS512')
        self.maabe = MaabeRW15(self.group)
        (self.pk, self.sk) = self.maabe.authsetup(public_parameters, nodeId)  # 节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
        # print(self.public_key1, self.secret_key1)

        self.public_parameters = public_parameters
        self.pks = {}  # 存储k轮的所有公钥
        self.com = {}  # 存储所有的commit
        # self.Re_1All = 0
        self.node_name = nodeId
        self.n = 5
        self.t = 3

        self.keys = {}
        self.cts = {}
        self.ctsDict = {}
        self.fSign = {}
        self.msg = {}
        # self.Com = {} #作为leader时的新commitment
        self.propose = {}
        self.sync = {}

        self.LL = queue.Queue()  # Leader List
        self.CL = []
        self.l = -1
        self.Re_1 = None  # 0号随机初始化R_{-1}
        self.s = None  # 上一个秘密值
        self.sl = None  # leader公布的s值
        self.comsl = None  # leader s的commitment
        self.newcom = None  # leader 新的commitment

    def getCandicateLeaders(self):
        clIds = []
        for i in range(0, len(self.CL)):
            clIds.append(self.CL[i]["id"])
        return clIds

    def get_PP(self):
        return {'g1' :self.public_parameters['g1'],
                'g2' :self.public_parameters['g2'],
                'egg':self.public_parameters['egg']
                }

    def set_PP(self, pp):
        self.public_parameters['g1']  = pp['g1']
        self.public_parameters['g2']  = pp['g2']
        self.public_parameters['egg'] = pp['egg']
        self.n = pp['n']
        self.t = int(self.n *2/3)+1
        (self.pk, self.sk) = self.maabe.authsetup(self.public_parameters, self.node_name)

    def newCom(self,k,s):
        Com = self.random_ct(k,s)
        Com["id"] = self.node_name
        Com["k"] = k
        return Com

    # def getLeaderCom(self):
    #     return self.Com

    # def addCom(self, nodeId, com):
    #     self.com[nodeId] = com

    def addPK(self, nodeId, pk):
        self.pks[nodeId] = pk

    def random(self):
        return  self.group.random(GT)
    def random_ct(self, k,random,policy=None):
        global CTnum, result
        if policy is None:
            temp = []
            for name in self.pks:
                temp.append(str(k) + '@' + name)
            policy = ', '.join(temp)
            policy = '(' + str(self.t) + ' of (' + policy + '))'


        cipher_text = self.maabe.encrypt(self.public_parameters, self.pks, random, policy)

        # CTnum += 1
        # if result == 0:
        #     result = eval(str(random))[0]
        # else:
        #     result ^= eval(str(random))[0]
        #
        # if CTnum == self.n:
        #     print("referrence",result)
        #     CTnum = 0
        #     result = 0

        return cipher_text
    # 传入轮次k和gid，返回对属性密钥的分享
    def generate_key(self, k, gid):
        user_key = self.maabe.multiple_attributes_keygen(self.public_parameters, self.sk, gid, [str(k)+'@'+self.node_name])
        if k not in self.keys:
            self.keys[k] = {'GID': gid, 'keys': user_key}
            # print(sys.getsizeof( self.keys[k]))
        else:
            self.keys[k]['keys'].update(user_key)

        return user_key

    # 传入轮次k和属性密钥分享，可选传入gid（最好传入），返回布尔值表示是否执行成功
    def add_key(self, k, user_key, gid=None):
        if gid is None:
            if k not in self.keys:
                print('need gid!')
                return False
        else:
            if k in self.keys:
                if gid != self.keys[k]['GID']:
                    print('gid is wrong!')
                    return False

        if k not in self.keys:
            self.keys[k] = {'GID': gid, 'keys': user_key}
        else:
            self.keys[k]['keys'].update(user_key)
        return True

    # 传入密文和轮次，返回解密结果
    def decrypt_num(self, cipher_text, k):
        return self.maabe.decrypt(self.public_parameters, self.keys[k], cipher_text)

    # 使用私钥签名，仅本节点能调用
    def sign(self, message):
        typemsg = str(type(message))
        if typemsg != "<class 'str'>" and typemsg != "<type 'str'>":
            print(type(message))
            raise Exception("the message to sign must be string")
        return self.public_parameters['H'](message) ** self.sk["y"]

    # 其他人使用公钥验签
    def verifySig(self,sig, message, public_key):
        # message = str(newjson.loads(newjson.dumps(message)))
        sig = newjson.loads(newjson.dumps(sig))

        # if type(sig) != "<class 'pairing.Element'>":
        #     raise Exception("signature  must be pairing.Element type")
        return pair(sig, self.public_parameters['g1']) == pair(self.public_parameters['H'](message), public_key["gy"])

    # 使用公钥加密
    def encrypt(self, message=None):
        if message == None:
            message = self.group.random(G1)
        r = self.group.random()
        return {
            "c1":public_parameters['g1']**r,
            "c2": message*(self.pk["gy"] ** r)
        }
    def decrypt(self, ciphertext):
        return ciphertext["c2"]/(ciphertext["c1"]**self.sk["y"])


if __name__ == '__main__':

    group = PairingGroup('SS512')
    maabe = MaabeRW15(group)
    public_parameters = maabe.setup() # 初始化global setup，返回全局公共参数public_parameters
    from charm.core.math.pairing import pairing, pc_element, ZR, G1, G2, GT, init, pair
    message2 = pair(group.random(G1),group.random(G2))

    # Setup the attribute authorities
    attributes1 = ['ONE', 'TWO']
    attributes2 = ['THREE', 'FOUR']
    (public_key1, secret_key1) = maabe.authsetup(public_parameters, 'UT') #节点UT作为权限授予中心，执行setup，返回公私钥对(pk,sk)
    (public_key2, secret_key2) = maabe.authsetup(public_parameters, 'OU') #节点OU作为权限授予中心，执行setup，返回公私钥对(pk,sk)
    public_keys = {'UT': public_key1, 'OU': public_key2} # pk通过P2P网络共享后，收到的pk集合

        # Setup a user and give him some keys
    gid = "bob" # The global user identifier 用作标记轮次？
    user_attributes1 = ['STUDENT@UT', 'PHD@UT'] # user_attributes1 = ['k@node1']
    user_attributes2 = ['STUDENT@OU']           # user_attributes2 = ['k@node2']

            # Create a random message
    message = group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
    # message2 =group.random(GT) # t_0时刻, 各节点（以节点i为例）生成随机数Mi
    # Encrypt the message
    access_policy = '(2 of (STUDENT@UT, PROFESSOR@OU, (XXXX@UT or PHD@UT))) and (STUDENT@UT or MASTERS@OU)'
    # t_0时刻, 构造 access_policy = '(t of (k@node1, k@node2, ... k@nodeN))'
    cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy) # t_0时刻, 各节点（以节点i为例）生成CTi
    cipher_text2 = maabe.encrypt(public_parameters, public_keys, message2, access_policy) # t_0时刻, 各节点（以节点i为例）生成CTi
    cipher_text3 = maabe.divideCT(cipher_text, cipher_text2)
    # print(cipher_text3)
    # t0~t1 广播CTi
    # t1~t2 得到诚实节点的[CTj]

    user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1) # node1生成的密钥key1,t2~t3广播
    user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2) # node2生成的密钥key2,t2~t3广播
    user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)} # t3时刻 各节点合成当前轮次的私钥key_k


            # Decrypt the message
    decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text3) #t3时刻，解密得到[Mi]
    print(decrypted_message == message/message2,message2)

# import time,sys
# if __name__ == '__main__':

#     maxNode = int(sys.argv[1])
#     group = PairingGroup('SS512')
#     maabe = MaabeRW15(group)

#     public_parameters = maabe.setup()  # 初始化global setup，返回全局公共参数public_parameters
#     print(1/(group.random()+group.random()))
#     gid = "K"
#     keyPaires = {}
#     public_keys = {}  # pk通过P2P网络共享后，收到的pk集合
#     user_attributes = {}
#     for i in range(0,maxNode):
#         keyPaires["AA%d"%i] = maabe.authsetup(public_parameters, "AA%d"%i)
#         public_keys["AA%d"%i] = keyPaires["AA%d"%i][0]
#         user_attributes["AA%d"%i] = ["%s@AA%d"%(gid,i)]

#     report = {}

#     for nodeNum in range(2, maxNode):
#         t = nodeNum/2
#         rIndex = "%d-%d" % (t,nodeNum)
#         report[rIndex] = {}
#         message = group.random(GT)
#         nattributes = ["%s@AA%d"%(gid,j) for j in range(0,nodeNum)]
#         access_policy = '(%d of (%s))'%(t,", ".join(nattributes))
#         t1 = time.time()
#         cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)  # t_0时刻, 各节点（以节点i为例）生成CTi
#         t2 = time.time()
#         report[rIndex]["enc"] = float('%.3f' % (t2 - t1))
#         user_keys = {'GID': gid, 'keys': merge_dicts2(
#             [maabe.multiple_attributes_keygen(public_parameters, keyPaires["AA%d"%j][1], gid, user_attributes["AA%d"%j]) for j in range(0,nodeNum)])}
#         t3 = time.time()
#         report[rIndex]["keygen"] = float('%.3f' % (t3 - t2))
#         decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
#         t4 = time.time()
#         report[rIndex]["dec"] = float('%.3f' % (t4 - t3))

#         t = nodeNum *2/3
#         rIndex = "%d-%d" % (t, nodeNum)
#         report[rIndex] = {}
#         message = group.random(GT)
#         nattributes = ["%s@AA%d" % (gid, j) for j in range(0, nodeNum)]
#         access_policy = '(%d of (%s))' % (t, ", ".join(nattributes))
#         print(access_policy)
#         t1 = time.time()
#         cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)  # t_0时刻, 各节点（以节点i为例）生成CTi
#         t2 = time.time()
#         report[rIndex]["enc"] = float('%.3f' % (t2 - t1))
#         user_keys = {'GID': gid, 'keys': merge_dicts2(
#             [maabe.multiple_attributes_keygen(public_parameters, keyPaires["AA%d" % j][1], gid,
#                                               user_attributes["AA%d" % j]) for j in range(0, nodeNum)])}
#         t3 = time.time()
#         report[rIndex]["keygen"] = float('%.3f' % (t3 - t2))
#         decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)  # t3时刻，解密得到[Mi]
#         t4 = time.time()
#         report[rIndex]["dec"] = float('%.3f' % (t4 - t3))

#         # print(decrypted_message == message)
#     open("maabe_report.json","w").write(newjson.dumps(report))
#     print(report)