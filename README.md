# attribute-based publicly verifiable secret sharing (AB-PVSS) scheme

This is the proof of concept implementation of attribute-based publicly verifiable secret sharing (AB-PVSS) scheme. 


### python3 abpvss.py 2

It invokes dabe.py and implement NIZK proofs to achieve AB-PVSS scheme. The NIZK proofs are obtained using Sigma protocol and Fiat-Shamir heuristic. 

### python3 dabe.py

Test the proposed decentralized CP-ABE.

### python3 scrapeDBS.py

Test the DBS version of SCRAPE PVSS scheme proposed in ACNS'17. Refer to [SCRAPE PVSS](https://eprint.iacr.org/2017/216.pdf)

### python3 scrapeDDH.py

Test the DDH version of SCRAPE PVSS scheme proposed in ACNS'17. Refer to [SCRAPE PVSS](https://eprint.iacr.org/2017/216.pdf)


### python3 Albatross.py

Test Albatross PVSS scheme proposed in ASIACRYPT'20. Refer to [Albatross PVSS](https://eprint.iacr.org/2020/644.pdf)


### python3 bsw07.py

Test the BSW CP-ABE proposed in S&P'07. Refer to [BSW CP-ABE](https://hal.archives-ouvertes.fr/hal-01788815/file/cp-abe.pdf)

### python3 dabe11.py

Test the decentralized LW CP-ABE proposed in Crypto'11. Refer to [LW CP-ABE](https://link.springer.com/content/pdf/10.1007/978-3-642-20465-4_31.pdf)

### python3 dabe15.py

Test the decentralized RW CP-ABE proposed in FC'15.  Refer to [RW CP-ABE](https://eprint.iacr.org/2015/016.pdf)
