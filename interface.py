# coding=utf-8
from charm.toolbox.pairinggroup import *
from newma import MaabeRW15


class Interface:
    def __init__(self):
        self.pks = {}  # 存储k轮的所有公钥
        self.pairing_group = 'SS512'  # 默认群
        self.public_parameters = {}
        self.group = PairingGroup(self.pairing_group)
        self.maabe = MaabeRW15(self.group)
        self.node_name = ''
        self.t = 15
        self.n = 21
        self.pk = None
        self.sk = None
        self.keys = {}

    # 获取当前群名
    def get_pairing_group(self):
        return self.pairing_group

    # 传入新的群名、公共参数和节点名，并设置相应的新类，返回新的公私钥对
    def set_pairing_group(self, pairing_group, public_parameters, node_name):
        self.pairing_group = pairing_group
        self.group = PairingGroup(self.pairing_group)
        self.maabe = MaabeRW15(self.group)

        return self.node_setup(public_parameters, node_name)

    def get_n(self):
        return self.n

    def set_n(self, n):
        self.n = n

    def get_t(self):
        return self.t

    def set_t(self, t):
        self.t = t

    # 全局调用一次，返回生成的公共参数
    def setup(self):
        return self.maabe.setup()

    # 节点运行的初始化函数，传入公共参数和节点名字，返回公私钥对
    def node_setup(self, public_parameters, node_name):
        self.public_parameters = public_parameters
        self.node_name = node_name

        pk, sk = self.maabe.authsetup(public_parameters, node_name)
        self.pks.clear()
        self.pks[node_name] = pk
        self.pk = pk
        self.sk = sk

        return pk, sk

    # 保存其他人的公钥（目前存在内存中）
    # TODO：将公私钥存在文件中
    def add_pk(self, public_key, node_name):
        self.pks[node_name] = public_key

    # 获取自身公钥
    def get_pk(self):
        return self.pk

    # 获取加密随机数，传入轮次k，可选policy，返回密文
    def random_ct(self, k, policy=None):
        if policy is None:
            temp = []
            for name in self.pks:
                temp.append(str(k) + '@' + name)
            policy = ', '.join(temp)
            policy = '(' + str(self.t) + ' of (' + policy + '))'
        random = self.group.random(GT)
        cipher_text = self.maabe.encrypt(self.public_parameters, self.pks, random, policy)

        return cipher_text

    # 传入轮次k和gid，返回对属性密钥的分享
    def generate_key(self, k, gid):
        user_key = self.maabe.multiple_attributes_keygen(self.public_parameters, self.sk, gid, [str(k)+'@'+self.node_name])
        if k not in self.keys:
            self.keys[k] = {'GID': gid, 'keys': user_key}
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


