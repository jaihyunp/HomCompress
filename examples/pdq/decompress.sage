from sage.all_cmdline import *   # import sage library
_sage_const_65537 = Integer(65537); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0); _sage_const_1 = Integer(1)
import numpy as np
from sage.doctest.util import Timer

def elementary_symmetric_polys(ind, R):
    s = len(ind)
    ele = [R(_sage_const_0 ) for i in range(s + _sage_const_1 )]

    ele[_sage_const_0 ] = R(_sage_const_1 )
    for k in range(_sage_const_1 , s + _sage_const_1 ):
        for i in range(_sage_const_1 , k + _sage_const_1 ):
            if (i - _sage_const_1 ) & _sage_const_1  == _sage_const_0 :
                ele[k] += ele[k - i] * ind[i - _sage_const_1 ]
            else:
                ele[k] -= ele[k - i] * ind[i - _sage_const_1 ]
        ele[k] /= R(k)
    return ele


# Read the compression
data = open("./ans.csv", "r").read().replace('[','').replace(']','')
data = np.fromstring(data, sep=',').astype(int)
n = len(data)
p = _sage_const_65537 
R = IntegerModRing(p)
ind = [R(datum) for datum in data[:n//_sage_const_2 ]]
dat = [R(datum) for datum in data[n//_sage_const_2 :]]


timer1 = Timer().start()

# Recover the index vector
ele = elementary_symmetric_polys(ind, R)
s = len(ind)
x = R['x'].gen(0)
f = _sage_const_0 
for d in range(s + _sage_const_1 ):
    if d & _sage_const_1  == _sage_const_0 :
        f += ele[s - d] * x**d
    else:
        f -= ele[s - d] * x**d
F = f.factor();
F.unit()
roots = [-list(p[_sage_const_0 ])[_sage_const_0 ] for p in list(F)][::-_sage_const_1 ]
if _sage_const_0  in roots:
    roots.remove(_sage_const_0 )

# Recover the data
s = len(roots)
pow = matrix(R, s, roots)
V = matrix(R, s, roots)
for i in range(s - _sage_const_1 ):
    for j in range(s):
        pow[j] *= roots[j]
    V = V.augment(pow)
V = V.transpose()

VDX = matrix(R, s, dat[:s])
answer = V**(-_sage_const_1 )*VDX
timer1.stop()

print("Result: ", answer.T)

# Print out the result
print("Timing for decompression: ", timer1.walltime)

