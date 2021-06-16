# coding=utf-8
from interface import Interface

if __name__ == '__main__':
    third_party = Interface()
    public_parameters = third_party.setup()

    NODE1 = Interface()
    NODE2 = Interface()
    NODE3 = Interface()

    pk1, _ = NODE1.node_setup(public_parameters, 'NODE1')
    pk2, _ = NODE2.node_setup(public_parameters, 'NODE2')
    pk3, _ = NODE3.node_setup(public_parameters, 'NODE3')

    NODE1.set_t(2)
    NODE1.set_n(3)
    NODE2.set_t(2)
    NODE2.set_n(3)
    NODE3.set_t(2)
    NODE3.set_n(3)

    NODE1.add_pk(public_key=pk2, node_name='NODE2')
    NODE1.add_pk(public_key=pk3, node_name='NODE3')
    NODE2.add_pk(public_key=pk1, node_name='NODE1')
    NODE2.add_pk(public_key=pk3, node_name='NODE3')
    NODE3.add_pk(public_key=pk2, node_name='NODE2')
    NODE3.add_pk(public_key=pk1, node_name='NODE1')
    # circular

    # step 4.1
    ct1 = NODE1.random_ct(k=1)
    ct2 = NODE2.random_ct(k=1)
    ct3 = NODE3.random_ct(k=1)

    # step 4.2+4.3
    cts = [ct1, ct2, ct3]

    # step 4.4
    user_key1 = NODE1.generate_key(k=1, gid='test')
    user_key2 = NODE2.generate_key(k=1, gid='test')

    # step 4.5
    NODE1.add_key(k=1, user_key=user_key2, gid='test')
    NODE2.add_key(k=1, user_key=user_key1, gid='test')

    # 测试异步
    NODE3.add_key(k=1, user_key=user_key1, gid='test')
    NODE3.add_key(k=1, user_key=user_key2, gid='test')
    user_key3 = NODE3.generate_key(k=1, gid='test')

    NODE1.add_key(k=1, user_key=user_key3, gid='test')
    NODE2.add_key(k=1, user_key=user_key3, gid='test')

    # step 4.6
    for ct in cts:
        m1 = NODE1.decrypt_num(ct, k=1)
        m2 = NODE2.decrypt_num(ct, k=1)
        m3 = NODE3.decrypt_num(ct, k=1)
        assert m1 == m2 == m3, 'wrong'
    print('Done!')

