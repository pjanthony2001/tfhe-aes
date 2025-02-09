# tfhe-aes
tFHE implementation of AES


# Brief Overview
This work is an implementation of AES in multiple modes (EBC, CBC, OFB, etc) that works in FHE. Our approach follows mostly this paper [Efficient Implementation of AES in 32 bit systems](https://link.springer.com/content/pdf/10.1007/3-540-36400-5_13.pdf), namely working with transposed state matrices improved performance. Furthermore, we decided to implement AES using the `tfhe::boolean` API, as we found that the "SubBytes" operation takes too much time using standard `FHEUint` types. To improve the performance of the `SubBytes` operation, we implemented a 8-bit multiplexer in the form of a boolean tree to represent each `SBOX`, which we then reduced using basic boolean logic to have the fewest operations possible. Evaluation of this boolean tree was done in a staged manner to allow for the most parallelism. 

During our research we came across multiple other papers implementing AES using FHE, namely: 
[Leveled Functional Bootstrapping via External Product Tree]()
[At Last! A Homomorphic AES Evaluation in Less than 30 Seconds by Means of TFHE]()

which had implemented new primitives and methods that enabled faster simultaneous bootstrapping operations and yielded much faster results. However, we have not tested whether these results were achieved with the security parameters as outlined in the challenge, yet they are definitely much faster than our implementation.

# In-depth Explanation

In this explanation, we will skim over the details of AES itself, and rather focus on the different parts of our solution that are unique.

## FHEByte
Firstly, we can see from the AES implementation that addition and subtraction of integers as a method is not used. As such, it would make sense to implement a FHEByte that uses all 8 bits for encryption (instead of 4 for message, and 4 for carry-over). The FHEByte is a wrapper around `[tfhe::boolean; 8]`, and we have implemented the standard logical methods (such as `xor`, `and`, `not`, 'shift-left' etc.), and other methods for convenience such as instantiating as from the clear `bool` or `u8`, or encrypted ones. 

## Boolean-tree and Multiplexer
The sub-bytes operation is the main source of performance cost for the AES-implementation. In ordinary clear implementations, there is usually an array `SBOX` such that indexing this array would give you the substitution: `sub-word(x) = SBOX[x]`. We decided to implement this array accessing by encoding it as an 8-bit multiplexer, where 

### Staging

## AES implementation

