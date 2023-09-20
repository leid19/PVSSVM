#第二版*****************************************************************************************************************
import random
from math import ceil
import numpy as np
from decimal import Decimal

FIELD_SIZE = 20
MOD = 9999999987


def coeff(t, secret):
    """
    生成最高次为t - 1次的多项式，其中常数项是secret
    """
    # 保证第一项不为0
    #coeff = [random.randrange(1, FIELD_SIZE,len(secret))]
    n = len(secret)
    coeff = []
    coeff.append([x for x in np.random.randint(1,FIELD_SIZE,size=(1,n))[0]])
    # 后面t - 2系数项可为0
    if t > 1:
        for _ in range(t-2):
            coeff.append([x for x in np.random.randint(0, FIELD_SIZE, size=(1, n))[0]])

    # 加入常数项
    coeff.append(secret)
    return coeff


def polynom(x, coefficients):
    """
    获取f(x)的值
    """
    point = 0
    # coeff从左到右是高次到低次的(使用enumerate表示指数)
    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):
        point = point + x ** coefficient_index * coefficient_value
    return point

def polynom_v1(x, coefficients):
    """
    获取f(x)的值
    """
    point = 0
    x = np.array([x]*len(coefficients[0]))
    # coeff从左到右是高次到低次的(使用enumerate表示指数)
    for coefficient_index, coefficient_value in enumerate(coefficients[::-1]):#倒序
        point = point + (x ** coefficient_index * coefficient_value)
    return point


def generate_shares(n, m, secret):
    """
    将秘密分成n份，只需要m份就可以复原（也就是阈值，函数的最高次数 + 1）
    """
    coefficient = coeff(m, secret)
    shares = []
    #xs = random.sample(range(0, FIELD_SIZE), n)#多用于截取列表的指定长度的随机数，但是不会改变列表本身的排序：
    xs = np.random.randint(1, FIELD_SIZE, size=(n, len(secret)))
    for i in range(1, n + 1):
        #x = xs[i - 1]
        x = np.array([i]*len(secret))
        #x = np.array([i])
        shares.append((x, polynom(x, coefficient)))
    return shares,coefficient


def reconstruct_secret(shares):
    """
    利用拉格朗日插值法（已知m个秘密)还原并得到secret(f(0))
    """
    sums = 0
    #print('shares',shares)
    shares = [(np.array([2, 2, 2, 2]), np.array([37, 72, 59, 100])), (np.array([5, 5, 5, 5]), np.array([166, 312, 308, 484])),(np.array([4, 4, 4, 4]), np.array([113, 214, 203, 324]))]
    #ls = shares[0][0].shape[0]
    #print('ls',ls)
    for j, share_j in enumerate(shares):
        xj, yj = share_j # 值  函数值
        prod = 1#*ls
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                #print(Decimal(Decimal(xi) / (xi - xj)))
                prod *= xi / (xi - xj)
        prod *= yj
        sums += prod
    return int(sum(sums)) 

def reconstruct_secret_v1(shares):
    """
    利用拉格朗日插值法（已知m个秘密)还原并得到secret(f(0))
    """
    sums = 0
    ls = shares[0][0].shape[0]
    #print('ls',ls)
    for j, share_j in enumerate(shares):
        xj, yj = share_j # 值  函数值
        prod = [1]*ls
        for i, share_i in enumerate(shares):
            xi, _ = share_i
            if i != j:
                #print(Decimal(Decimal(xi) / (xi - xj)))
                prod *= xi / (xi - xj)
        prod *= yj
        sums += prod
    return [ int(round(x, 0)) for x in sums]

# # Driver code  测试
if __name__ == '__main__':
    # (3,5) sharing scheme
    t, n = 3, 5
    secret = [1,2,3,4]
    print(f'Original Secret: {secret}')

    # Phase I: Generation of shares
    shares,coef = generate_shares(n, t, secret)
    print(f'Shares: {", ".join(str(share) for share in shares)}')

    # Phase II: Secret Reconstruction
    # Picking t shares randomly for
    # reconstruction
    pool = random.sample(shares, t)
    print('pool',pool)
    print(f'Combining shares: {", ".join(str(share) for share in pool)}')
    print(f'Reconstructed secret: {reconstruct_secret(pool)}')

