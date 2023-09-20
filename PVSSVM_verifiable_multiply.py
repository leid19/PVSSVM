#**********************************************************************************************************************************************************************
# BGN 
import gmpy2
import random
from pypbc import *
import numpy as  np
import  time
import math
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
#from niu_computation_overhead import get_prime,KeyGen,dec_list,pai
#from niu_computation_overhead import read_data,tfidf_vector   


def read_data():
    SMS_path="./dataset/SMSSpamCollection"
    Cnames = ['labels', 'messages']
    SMS_data = pd.read_csv(SMS_path, sep='\t', header=None, names=Cnames)
    SMS_data = SMS_data.replace({'ham': -1, 'spam': 1})  # replace  label
    return SMS_data  #[5572 rows x 2 columns]  dataframe
def tfidf_vector(data):
    corpus = list(data.iloc[0:,1])
    tfidf_vec = TfidfVectorizer(use_idf=True, smooth_idf=True, norm=None,max_features=500)
    tf_idf_matrix = tfidf_vec.fit_transform(corpus)
    tfidf_array = tf_idf_matrix.toarray() #tf-idf
    return  tfidf_array
def get_prime(rs=gmpy2.random_state(int(time.time()))):  # random state
    p = gmpy2.mpz_urandomb(rs, 20)  #
    while not gmpy2.is_prime(p) & gmpy2.is_prime((p - 1) // 2):
        p = p + 1
    return p
def KeyGen():
    q_1 = get_random_prime(9)  
    q_2 = get_random_prime(9)
    q = q_1 * q_2  # k

    params = Parameters(n=q)  
    pairing = Pairing(params)  
    g = Element.random(pairing, G1)  
    h = Element.random(pairing, G2)  

    s = Element.random(pairing, Zr)

    g1 = Element.random(pairing, G1)#GT
    g2 = Element.random(pairing, G1)#GT

    gs = g**s
    return [q, G1, G2, GT, h, pairing,(g, g ** s), (g1, g2)], s  # PK SK
def encipher(pk, plaintext):
    n = pk[0]
    g1, g2 = pk[-1][0], pk[-1][1]
    g, gs = pk[-2][0], pk[-2][1]

    m = plaintext
    r = random.randint(1, int(n / 4))

    c = (g1**plaintext * g**r, g2 ** m * gs ** r)
    return c,r

def enc_arry(m, pk):#
    C = []
    r_list = []
    for i in range(m.shape[0]):
        c = []
        for j in range(m.shape[1]):
            plaintext = int(m[i][j])
            x,r = encipher(pk, plaintext)
            c.append(x)
            r_list.append(r)
        C.append(c)
    return C,r_list

def decipher(pk,sk,c,pai):
    m = c[0] ** 20 * c[1] ** (-1)
    z = np.log10(11**10) / np.log10(9**10)  
    #math.log(m, pai) 
    return z

def dec_list(c,pk,sk,pai):
    m = []
    for i in range(len(c)) :
        for j in range (len(c[0])):
            ciphertext = c[i][j]
            if ciphertext != 0:
                x = decipher(pk,sk,ciphertext,pai)
                m.append(x)
            else:
                m.append(ciphertext)
    return m
from lei_shamir import *

SMS = read_data()
SMS_V1 = SMS
vector_SMS = tfidf_vector(SMS_V1)
label_SMS = list(SMS_V1.iloc[0:,0])

x_train, x_test, y_train, y_test = train_test_split(vector_SMS, label_SMS, test_size=0.996,random_state=0)
x_train1, x_test1, y_train1, y_test1 = train_test_split(vector_SMS, label_SMS, test_size=0.02,random_state=0)

#***********************************************************************************************************************
'''密钥生成模块'''
keygen_start = time.perf_counter()

pk,sk = KeyGen()
q = pk[0]
g1, g2 = pk[-1][0], pk[-1][1]
g, gs = pk[-2][0], pk[-2][1]

h = pk[4]
pairing = pk[5]

keygen_end = time.perf_counter()
keygen_time = -keygen_start + keygen_end###
print('密钥生成时间（单次）',keygen_time)
global pai
pai = g1**sk * g2**(-1)
z = x_test1
n = z.shape[1]

# #***********************************************************************************************************************
# '''Secure Dot Product'''
# def lu(l0,l1,u):
#     return l0 + l1*int(u)
# def G(Wl0,Wl1,u):
#     return Wl0 + Wl1 * u
#
# def dot_product(x,z,FGen_time,jiami_time,compute_time,yanzheng_time,gongkaiyanzheng_time,fuzhuyanzheng_time):
# # 1、KeyGen(τ)
# # 2、F Gen(λ, F,PK)
#     n = z.shape[1]
#
#     jiamimoxing_start = time.perf_counter()
#     # l0 = np.random.randint(0,q,size=(1,n))[0]# 等价m维度
#     # l1 = np.random.randint(0,q,size=(1,n))[0]
#     W = np.array(x)#初始化权重
#     # Wl0 = int(W.T.dot(l0))
#     # Wl1 = int(W.T.dot(l1))
# #加密模型权重
#     c_W,r_list = enc_arry(W.reshape(1,W.shape[0]),pk)
#     c_W = c_W[0] #分发给K个不同服务器
#     jiamimoxing_end = time.perf_counter()
#     # yanzheng1_start = time.perf_counter()  没有该环节
#     # #user
#     # h_wlo = h ** Wl0
#     # h_wl1 = h ** Wl1
#     # #model owner
#     # pkf = lu#函数
#     # vkf = (h_wlo,h_wl1)
#     # yanzheng1_end = time.perf_counter()
#     #FGen_time = FGen_time  + yanzheng1_end - yanzheng1_start + jiamimoxing_end - jiamimoxing_start
#     FGen_time = FGen_time  +  jiamimoxing_end - jiamimoxing_start
#     #return FGen_time
# #***********************************************************************************************************************
#     # 3、SGen    shamir
#     jiamisecret_start = time.perf_counter()
#     k,t = 5,3#服务器数量,合谋阈值
#     #构造g_fuction(u) 函数
#
#     #s = int(np.random.randint(0,q,size=(1)))
#     #cegm = int(np.random.randint(0,q,size=(1))/k)
#     aer = int(np.random.randint(0,q,size=(1)))
#
#     # s = np.random.randint(0,q,size=(1,n))[0]
#     # cegm = [int(x/k) for x in np.random.randint(0,q,size=(1,n))[0]]
#     #a = lu(l0,l1,sk)
#
#     secret_v1 = z[0]#单行
#     secret_v2 = [aer]*len(z[0])
#     shares_v1,coefficient_v1 = generate_shares(k, t, secret_v1)#将秘密分成k份，只需要t份就可以复原
#     #print('shares_v1',shares_v1)
#     shares_v2,coefficient_v2 = generate_shares(k, t, secret_v2)#将秘密分成k份，只需要t份就可以复原
#     #print('coefficient',len(coefficient),coefficient)
#     aerf_v1 = [list(x[1]) for x in shares_v1]#分发给K个服务器
#     #print('aerf_v1',len(aerf_v1),len(aerf_v1[0]))# 5 100
#     aerf_v2 = [list(x[1]) for x in shares_v2]#分发给K个服务器
#     aerf = [aerf_v1,aerf_v2]
#
#     #yanzheng2_start = time.perf_counter()
#
#     pvkX = [g**aer]
#     svkx = [aer]
#
#     #yanzheng2_end = time.perf_counter()
#     jiamisecret_end = time.perf_counter()
# #***********************************************************************************************************************
# # 4、Compute
# #计算板块，每个云计算中间结果
#     compute_start = time.perf_counter()
#     #print('aerf[i]',sum(aerf[0]),aerf[0])
#     vi = []
#     wbli = []
#     # for i in range(1):
#     #     #print('aerf[i][0]',type(aerf[i][0]),aerf[i][0])
#     #     Fi0 = c_W[0][0] ** int(aerf[i][0])
#     #     Fi1 = c_W[0][1] ** int(aerf[i][0])
#     #     for j in range(1,len(c_W)):
#     #         Fi0 = Fi0 * c_W[j][0]**int(aerf[i][j])
#     #         Fi1 = Fi1 * c_W[j][1]**int(aerf[i][j])
#     for i in range(k):
#         # print('aerf[i][0]',type(aerf[i][0]),aerf[i][0])
#         Fi0 = c_W[0][0] ** int(aerf[0][i][0])
#         Fi1 = c_W[0][1] ** int(aerf[0][i][0])
#
#         wbli0 = c_W[0][0] ** int(aerf[0][i][0] * aerf[1][i][0])
#         wbli1 = c_W[0][1] ** int(aerf[0][i][0] * aerf[1][i][0])
#
#         for j in range(1, len(c_W)):
#             Fi0 = Fi0 * c_W[j][0] ** int(aerf[0][i][j])
#             Fi1 = Fi1 * c_W[j][1] ** int(aerf[0][i][j])
#
#             wbli0 = wbli0 * c_W[0][0] ** int(aerf[0][i][j] * aerf[1][i][j])
#             wbli1 = wbli0 * c_W[0][1] ** int(aerf[0][i][j] * aerf[1][i][j])
#
#         vi.append([Fi0, Fi1])
#         wbli.append([wbli0, wbli1])
#
#     compute_end = time.perf_counter()
# #***********************************************************************************************************************
#     #5、 SecVer
#     #vkf svkx Fi sk
#     yanzheng3_start = time.perf_counter()
#     #print('wbli',wbli)
#     u_miu_v1 = dec_list(vi,pk,sk,pai)#(A,B)
#     u_miu_w1 = dec_list(wbli,pk,sk,pai)#(A,B)
#
#     #计算明文下的w*aerf进行替换 #############################
#     # u_miu_i = []
#     # #print(aerf,len(aerf))
#     # for x in range(k):
#     #     u_miu_i.append(W.T.dot(aerf[x]))
#
#     #取对数后获得 分别代入秘密共享的k个值的函数f（share-k）的值，用于插值求解 f(share)  原本的列表-》1个数
#     shares_vi = [(u_miu_v1[i],i+1) for i in range(k)]
#     shares_wi = [(u_miu_w1[i],i+1) for i in range(k)]
#
#     pool_vi = random.sample(shares_vi, t)
#     pool_wi = random.sample(shares_wi, t)
#     #print('u_miu_v1,pool_vi',u_miu_v1,pool_vi)
#     eqution_left = aer * reconstruct_secret(pool_vi)
#     eqution_right = reconstruct_secret(pool_wi)
#     result = eqution_left==eqution_right
#     #print('点积_私有验证等式_验证',eqution_left==eqution_right)
#     yanzheng3_end = time.perf_counter()
#     # accept_result = polynom_v1(0, coefficient[0])#验证成功后
#     # pool = [(shares[x][0],u_miu_i[x]) for x in range(len(shares))]
#     # print('z0',z[0])
#     # print('点积运算秘密恢复值',reconstruct_secret_v1(pool)[0])
#     # print('accept_result',accept_result)
#     #6、 PubVec
#
#     gongkaiyanzheng_start = time.perf_counter()
#
#     #u_miu = dec_list([Fi],pk,sk,pai)#(A,B)
#     u_miu_v1 = dec_list([vi],pk,sk,pai)#(A,B)
#     u_miu_w1 = dec_list([wbli],pk,sk,pai)#(A,B)
#     pool_vi = random.sample(u_miu_v1, t)
#     pool_wi = random.sample(u_miu_w1, t)
#
#     eqution_left = reconstruct_secret(pool_vi)
#     eqution_right = reconstruct_secret(pool_wi)
#     #pubver_result = (pairing.apply(h,g**int(np.sum(polynom_v1(cegm, coefficient)))) == pairing.apply(h,g**G(Wl0,Wl1,int(sk))))
#     pubver_result = pvkX[0]**(eqution_left) == g ** eqution_right
#     #pubver_result = (pairing.apply(h,g**int(polynom_v1(cegm, coefficient[0]))) == pairing.apply(vkf[0],g) * pairing.apply(pvkX[0],g))
#     #print('Pubvec',pubver_result,pairing.apply(h,g**int(polynom_v1(cegm, coefficient[0]))) , pairing.apply(vkf[0],g) * pairing.apply(pvkX[0],g))
#     gongkaiyanzheng_end = time.perf_counter()
#
#     gongkaiyanzheng_time = gongkaiyanzheng_time + gongkaiyanzheng_end - gongkaiyanzheng_start
#     #yanzheng_time = yanzheng_time + yanzheng1_end + yanzheng2_end + yanzheng3_end - yanzheng1_start - yanzheng2_start - yanzheng3_start
#     yanzheng_time = yanzheng_time  + yanzheng3_end  - yanzheng3_start
#     compute_time = compute_time + compute_end - compute_start
#     #jiami_time = jiami_time + jiamimoxing_end + jiamisecret_end - jiamimoxing_start - jiamisecret_start
#     jiami_time = jiami_time  + jiamisecret_end  - jiamisecret_start
#
#     fuzhuyanzheng_time = fuzhuyanzheng_time #+ yanzheng1_end + yanzheng2_end  - yanzheng1_start - yanzheng2_start
#     return [eqution_left,eqution_right],jiami_time,compute_time,yanzheng_time,gongkaiyanzheng_time,fuzhuyanzheng_time,pvkX
# #测试：
# z = np.round(x_test1).astype(int)
# n = z.shape[1]
# # x = [1]*n#模型权重
# x = x_train
# jiami_time=0
# compute_time=0
# yanzheng_time=0
# gongkaiyanzheng_time=0
# fuzhuyanzheng_time = 0
# FGen_time = 0
# verifys_all = []
# verifys_one = []
# # for i in z:  #计算点积
# #    #verifys_one = []
# #    for j in x:#支持向量 权重
# #        FGen_time = dot_product(j, i.reshape(1,i.shape[0]),FGen_time,jiami_time, compute_time, yanzheng_time, gongkaiyanzheng_time,fuzhuyanzheng_time)
# # print('点积-FGen',FGen_time)
# for i in z:
#    #verifys_one = []
#    for j in x:#支持向量 权重
#        vs,jiami_time, compute_time, yanzheng_time, gongkaiyanzheng_time,fuzhuyanzheng_time,pvkX = \
#            dot_product(j, i.reshape(1,i.shape[0]),FGen_time,jiami_time, compute_time, yanzheng_time, gongkaiyanzheng_time,fuzhuyanzheng_time)
#        verifys_one.append(vs)
#    verifys_all.append(verifys_one)
# print('支持向量',x,len(x))
# print('输入数据',z,len(z))
# print('密钥生成时间（单次）',keygen_time)
# print('加密',jiami_time,'秘密计算',compute_time/5)
# print('辅助参数',fuzhuyanzheng_time,'验证',yanzheng_time,'公开验证',gongkaiyanzheng_time)
# #私有验证 批量验证
# t1_start = time.perf_counter()
# hcegm = 0
# hs = 0
# for x in verifys_all[0]:
#     hcegm = hcegm + x[0]
#     hs = hs + x[1]
# result1 = hs == hcegm
# t1_end = time.perf_counter()
# print('私有验证 批量验证 时间',t1_end-t1_start)
# print('加辅助验证时间',t1_end-t1_start+fuzhuyanzheng_time)
# #公开验证 批量验证
# t2_start = time.perf_counter()
# hcegm = 0
# hs = 0
# for x in verifys_all[0]:
#     hcegm = hcegm + x[0]
#     hs = hs + x[1]
# pubver_result = pvkX[0]**(hcegm) == g ** hs
# t2_end = time.perf_counter()
# print('公开验证 批量验证 时间',t2_end-t2_start)
# print('点积距离*********************************************************************************************************')
#print('加辅助验证时间',t2_end-t2_start+fuzhuyanzheng_time)
'''***********************************************************************************************************************'''
'''Secure Squared Euclidean Distance'''
# 1、Keygen
#步骤同前
# def G_v1(W,l0_v1,l1_v1,u):
#     result = 0
#     for x in range(n):
#         result = result + (int(W[x]-l0_v1[x])**2 + 2*l1_v1[x]*(l0_v1[x]-W[x])*u + l1_v1[x]**2 * u**2)
#     return result

def square(x,z,Fgen_time,jiami_time,compute_time,yanzheng_time,gongkaiyanzheng_time):
# 2、F Gen(λ, F,PK)
    Fgen_start = time.perf_counter()
    #l0_v1 = np.random.randint(0,q,size=(1,n))[0]# 等价m维度
    #l1_v1 = np.random.randint(0,q,size=(1,n))[0]
    W = np.array(x)#初始化权重
    # def lu(l0,l1,u):return l0 + l1*u
    #模型权重及其平方加密
    #print(W.shape,W)
    c_W_v1,r_list1 = enc_arry(W.reshape(1,W.shape[0]),pk)
    c_W_v1 = c_W_v1[0] #分发给K个不同服务器
    W2 = np.array([x**2 for x in W])
    c_W_v2,r_list2 = enc_arry(W2.reshape(1,W2.shape[0]),pk)
    c_W_v2 = c_W_v2[0] #分发给K个不同服务器
    #计算辅助因子
    #hwl1_v1 = h ** int(sum([(W[x]-l1_v1[x])**2 for x in range(n)]))
    #hwl10_v2 = h ** int(sum([2 * l1_v1[x] * (-W[x]+l0_v1[x]) for x in range(n)]))
    #hwl1_v3 = h ** int(sum([(l1_v1[x])**2 for x in range(n)]))
    #vkf_v1 = (hwl1_v1,hwl10_v2,hwl1_v3)

    #print('欧氏距离计算辅助项',vkf_v1)
    Fgen_end = time.perf_counter()
    Fgen_time = Fgen_time + Fgen_end - Fgen_start
    return Fgen_time

    #3、 SGen(pkF , vkF , X).
    jiamisecret_start = time.perf_counter()
    k,t = 5,3


    aer = int(np.random.randint(0,q,size=(1)))

    secret_v1 = z[0]#单行
    secret_v2 = [aer]*len(z[0])
    shares_v1,coefficient_v1 = generate_shares(k, t, secret_v1)#将秘密分成k份，只需要t份就可以复原

    shares_v2,coefficient_v2 = generate_shares(k, t, secret_v2)#将秘密分成k份，只需要t份就可以复原

    aerf_v1 = [list(x[1]) for x in shares_v1]#分发给K个服务器
    aerf_v2 = [list(x[1]) for x in shares_v2]#分发给K个服务器
    aerf = [aerf_v1,aerf_v2]

    pvkX = [g**aer]
    svkx = [aer]

    jiamisecret_end = time.perf_counter()

    # 4、Compute(i, [ [fi] ], αi)
    #密文下计算中间结果
    #print('c_W_v2',c_W_v2)

    compute_start = time.perf_counter()
    Fi_v1 = []
    wbli = []
    for i in range(k):
        Fi0_v1 = c_W_v2[i][0] * (c_W_v1[i][0] ** int(-2 * aerf_v1[i][0])) * (g1 ** int(aerf_v1[i][0] ** 2))
        Fi1_v1 = c_W_v2[i][1] * (c_W_v1[i][1] ** int(-2 * aerf_v1[i][0])) * (g2 ** int(aerf_v1[i][0] ** 2))

        wbli0_v1 = c_W_v2[i][0] * (c_W_v1[i][0] ** int(-2 * aerf_v1[i][0])) * (g1 ** int(aerf_v1[i][0] ** 2)) * aerf[1][i][0]
        wbli1_v1 = c_W_v2[i][1] * (c_W_v1[i][1] ** int(-2 * aerf_v1[i][0])) * (g2 ** int(aerf_v1[i][0] ** 2)) * aerf[1][i][0]

        for j in range(1, len(c_W_v1)):
            Fi0_v1 = Fi0_v1 * c_W_v2[i][0] * (c_W_v1[i][0] ** int(-2 * aerf_v1[i][j])) * (g2 ** int(aerf_v1[i][j] ** 2))
            Fi1_v1 = Fi1_v1 * c_W_v2[i][1] * (c_W_v1[i][1] ** int(-2 * aerf_v1[i][j])) * (g2 ** int(aerf_v1[i][j] ** 2))
            wbli0_v1 = wbli0_v1 * c_W_v2[i][0] * (c_W_v1[i][0] ** int(-2 * aerf_v1[i][0])) * (g1 ** int(aerf_v1[i][0] ** 2)) * aerf[1][i][0]
            wbli1_v1 = wbli1_v1 * c_W_v2[i][1] * (c_W_v1[i][1] ** int(-2 * aerf_v1[i][0])) * (g2 ** int(aerf_v1[i][0] ** 2)) * aerf[1][i][0]

        Fi_v1.append([Fi0_v1, Fi1_v1])
        wbli.append([wbli0_v1, wbli1_v1])

    compute_end = time.perf_counter()

    # 5、SecVer(vkF, svkX, {[ [φi] ]}ki=1, SK)
    #明文下计算结果进行替换

    #验证
    yanzheng3_start = time.perf_counter()
    u_miu_v1 = dec_list(Fi_v1,pk,sk,pai)#(A,B)
    u_miu_w1 = dec_list(wbli,pk,sk,pai)#(A,B)
    #取对数后获得 分别代入秘密共享的k个值的函数f（share-k）的值，用于插值求解 f(share)  原本的列表-》1个数
    shares_vi = [(u_miu_v1[i],i+1) for i in range(k)]
    shares_wi = [(u_miu_w1[i],i+1) for i in range(k)]

    pool_vi = random.sample(shares_vi, t)
    pool_wi = random.sample(shares_wi, t)
    eqution_left = aer * reconstruct_secret(pool_vi)
    eqution_right = reconstruct_secret(pool_wi)
    result = eqution_left==eqution_right

    yanzheng3_end = time.perf_counter()
    #接收 ϕ(0)

    # 6、PubV er(vkF, pvkX, {[ [φi] ]}ki=1, SK)
    #同样有一个解密过程
    gongkaiyanzheng_start = time.perf_counter()

    u_miu_v1 = dec_list(Fi_v1,pk,sk,pai)#(A,B)
    u_miu_w1 = dec_list(wbli,pk,sk,pai)#(A,B)
    pool_vi = random.sample(u_miu_v1, t)
    pool_wi = random.sample(u_miu_w1, t)

    eqution_left = reconstruct_secret(pool_vi)
    eqution_right = reconstruct_secret(pool_wi)

    pubver_result = pvkX[0]**(eqution_left) == g ** eqution_right

    gongkaiyanzheng_end = time.perf_counter()

    gongkaiyanzheng_time = gongkaiyanzheng_time + gongkaiyanzheng_end - gongkaiyanzheng_start
    #yanzheng_time = yanzheng_time + yanzheng1_end + yanzheng2_end + yanzheng3_end - yanzheng1_start - yanzheng2_start - yanzheng3_start
    yanzheng_time = yanzheng_time  + yanzheng3_end  - yanzheng3_start
    compute_time = compute_time + compute_end - compute_start
    #jiami_time = jiami_time + jiamimoxing_end + jiamisecret_end - jiamimoxing_start - jiamisecret_start
    jiami_time = jiami_time  + jiamisecret_end  - jiamisecret_start
    return [eqution_left,eqution_right],jiami_time,compute_time,yanzheng_time,gongkaiyanzheng_time,pvkX,svkx

# #测试
z = np.round(x_test1).astype(int)
n = z.shape[1]
# x = [1]*n#模型权重
x = x_train

jiami_time1=0
compute_time1=0
yanzheng_time1=0
gongkaiyanzheng_time1=0
Fgen_time1 = 0
for i in z:
   for j in x:
       Fgen_time1 = square(j, i.reshape(1,i.shape[0]),Fgen_time1,jiami_time1, compute_time1, yanzheng_time1, gongkaiyanzheng_time1)
print('欧式距离-FGen',Fgen_time1)

verifys_all = []
verifys_one = []
for i in z:
   #verifys_one = []
   for j in x:
       vs,jiami_time1, compute_time1, yanzheng_time1, gongkaiyanzheng_time1,pvkX,svkx = \
           square(j, i.reshape(1,i.shape[0]), jiami_time1, compute_time1, yanzheng_time1, gongkaiyanzheng_time1)
       verifys_one.append(vs)
   verifys_all.append(verifys_one)
print('支持向量',x,len(x))
print('输入数据',z,len(z))
print('密钥生成时间（单次）',keygen_time)
print('加密',jiami_time1,'秘密计算',compute_time1/5)
print('验证',yanzheng_time1,'公开验证',gongkaiyanzheng_time1)

#私有验证 批量验证  private   batch-pri
t1_start1 = time.perf_counter()
hcegm = 0
hs = 0
print(len(verifys_all[1]))
for x in verifys_all[1]:
    hcegm = hcegm + x[0]
    hs = hs + x[1]
result1 = svkx[0]*hs == hcegm
t1_end1 = time.perf_counter()
print('欧式距离 私有验证 批量验证 时间',t1_end1-t1_start1)
#公开验证 批量验证  public   bat-pub
t2_start1 = time.perf_counter()
hcegm = 0
hs = 0
for x in verifys_all[0]:
    hcegm = hcegm + x[0]
    hs = hs + x[1]
pubver_result = pvkX[0]**hcegm == g**hs
t2_end1 = time.perf_counter()
print('欧式距离 公开验证 批量验证 时间',t2_end1-t2_start1)

# '''***********************************************************************************************************************'''
# #假设模型所有者、云服务器和模型用户已经同意将浮点数据或参数转换为整数[22]的缩放和舍入公式。
# '''多项式核函数'''
# #模型所有者 加密 支持向量 W  将数据分成k份，调用compute 计算中间结果，并将其发送给模型使用者或第三方
# #模型使用者 验证，进行插值获得
#print('点积计算*********************************************************************************************************')
# print('密钥生成时间（单次）',keygen_time)
# print('加密',jiami_time,'秘密计算',compute_time/5)
# print('辅助参数',fuzhuyanzheng_time,'验证',yanzheng_time,'公开验证',gongkaiyanzheng_time)
# print('私有验证 批量验证 时间',t1_end-t1_start)
# print('公开验证 批量验证 时间',t2_end-t2_start)
