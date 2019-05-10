---
title: "Use of the Hash-based Signature Algorithm with CBOR Object Signing and Encryption (COSE)"
abbrev: HashSig with COSE
docname: draft-ietf-cose-hash-sig-03
date: 2019-05-10
category: std

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: no
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Housley
    name: Russ Housley
    org: Vigil Security, LLC
    abbrev: Vigil Security
    street: 516 Dranesville Road
    city: Herndon, VA
    code: 20170
    country: US
    email: housley@vigilsec.com

normative:
  HASHSIG:
    title: "Hash-Based Signatures"
    author:
      -
        name: David McGrew
        ins: D. McGrew
        org: Cisco Systems
      -
        name: Michael Curcio
        ins: M. Curcio
        org: Cisco Systems
      -
        name: Scott Fluhrer
        ins: S. Fluhrer
        org: Cisco Systems
    date: 2019-01
    seriesinfo:
       "draft-mcgrew-hash-sigs-15": "(work in progress)"
  RFC2119:
  RFC8152:
  RFC8174:
  SHS:
    title: Secure Hash Standard
    author:
      org: National Institute of Standards and Technology (NIST)
    date: 2008
    seriesinfo:
      "FIPS Publication": "180-3"

informative:
  RFC4086:
  RFC5280:
  BH2013:
    title: "The Factoring Dead: Preparing for the Cryptopocalypse"
    author:
      -
        name: Thomas Ptacek
        ins: T. Ptacek
        org: Matasano
      -
        name: Tom Ritter
        ins: T. Ritter
        org: iSEC Partners    
      -
        name: Javed Samuel
        ins: J. Samuel
        org: iSEC Partners    
      -
        name: Alex Stamos
        ins: A. Stamos
        org: Artemis Internet
    date: 2013-08
    target: https://media.blackhat.com/us-13/us-13-Stamos-The-Factoring-Dead.pdf
  LM:
    title: "Large provably fast and secure digital signature schemes from secure hash functions"
    author:
      -
        name: Frank T. Leighton
        ins: F. Leighton
      -
        name: Silvio Micali
        ins: S. Micali
    date: 1995-07-11
    seriesinfo:
      "U.S. Patent": "5,432,852"
  M1979:
    title: "Secrecy, Authentication, and Public Key Systems"
    author:
      name: Ralph Merkle
      ins: R. Merkle
    date: 1979
    seriesinfo:
      "Stanford University Information Systems Laboratory Technical Report": "1979-1"
  M1987:
    title: "A Digital Signature Based on a Conventional Encryption Function"
    author:
      name: Ralph Merkle
      ins: R. Merkle
    date: 1988
    seriesinfo:
      "Lecture Notes in Computer Science": "crypto87"
  M1989a:
    title: "A Certified Digital Signature"
    author:
      name: Ralph Merkle
      ins: R. Merkle
    date: 1990
    seriesinfo:
      "Lecture Notes in Computer Science": "crypto89"
  M1989b:
    title: "One Way Hash Functions and DES"
    author:
      name: Ralph Merkle
      ins: R. Merkle
    date: 1990
    seriesinfo:
      "Lecture Notes in Computer Science": "crypto89"
  PQC:
    title: "Introduction to post-quantum cryptography"
    author:
      name: Daniel J. Bernstein
      ins: D. Bernstein
      org: "Department of Computer Science, University of Illinois at Chicago"
    date: 2009
    target: http://www.pqcrypto.org/www.springer.com/cda/content/document/cda_downloaddocument/9783540887010-c1.pdf
  S1997:
    title: "Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer"
    author:
      name: Peter W. Shor
      ins: P. Shor
    date: 1997
    seriesinfo:
      "SIAM Journal on Computing": "26(5), 1484-26"
    target: http://dx.doi.org/10.1137/S0097539795293172

--- abstract

This document specifies the conventions for using the HSS/LMS
hash-based signature algorithm with the CBOR Object Signing and
Encryption (COSE) syntax.  The HSS/LMS algorithm is one form of
hash-based digital signature; it is described in RFC 8554.

--- middle

#Introduction {#intro}

This document specifies the conventions for using the HSS/LMS
hash-based signature algorithm with the CBOR Object Signing and
Encryption (COSE) {{RFC8152}} syntax.  The Leighton-Micali
Signature (LMS) system provides a one-time digital signature that
is a variant of Merkle Tree Signatures (MTS).  The Hierarchical
Signature System (HSS) is built on top of the LMS system to
efficiently scale for a larger  numbers of signatures.  The HSS/LMS
algorithm is one form of hash-based digital signature, and it is
described in {{HASHSIG}}.  The HSS/LMS signature algorithm can only
be used for a fixed number of signing operations.  The number of
signing operations depends upon the size of the tree.  The HSS/LMS
signature algorithm uses small public keys, and it has low computational
cost; however, the signatures are quite large.  The HSS/LMS private key
can be very small when the signer is willing to perform additional
computation at signing time; alternatively, the private key can consume
additional memory and provide a faster signing time.

##Algorithm Security Considerations

There have been recent advances in cryptanalysis and advances in
the development of quantum computers.  Each of these advances pose
a threat to widely deployed digital signature algorithms.

At Black Hat USA 2013, some researchers gave a presentation on the
current state of public key cryptography.  They said: "Current
cryptosystems depend on discrete logarithm and factoring which
has seen some major new developments in the past 6 months"
{{BH2013}}.  Due to advances in cryptanalysis, they encouraged
preparation for a day when RSA and DSA cannot be depended upon.

Peter Shor showed that a large-scale quantum computer could be used
to factor a number in polynomial time {{S1997}}, effectively breaking
RSA.  If large-scale quantum computers are ever built, these computers
will be able to break many of the public-key cryptosystems currently
in use.  A post-quantum cryptosystem {{PQC}} is a system that is secure
against quantum computers that have more than a trivial number of quantum
bits (qu-bits).  It is open to conjecture when it will be feasible to build
such computers; however, RSA, DSA, ECDSA, and EdDSA are all vulnerable if
large-scale quantum computers come to pass.

The HSS/LMS signature algorithm does not depend on the difficulty of
discrete logarithm or factoring, as a result these algorithms are
considered to be post-quantum secure.

Hash-based signatures {{HASHSIG}} are currently defined to use
exclusively SHA-256 {{SHS}}.  An IANA registry is defined so that other hash
functions could be used in the future.  LM-OTS signature generation
prepends a random string as well as other metadata before computing the
hash value.  The inclusion of the random value reduces the chances of an
attacker being able to find collisions, even if the attacker has a
large-scale quantum computer.

Today, RSA is often used to digitally sign software updates.  This
means that the distribution of software updates could be compromised
if a significant advance is made in factoring or a large-scale quantum
computer is invented.  The use of HSS/LMS hash-based signatures to
protect software update distribution, perhaps using the format that
is being specified by the IETF SUIT Working Group, will allow the
deployment of software that implements new cryptosystems.

##Terminology {#terms}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP&nbsp;14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in
all capitals, as shown here.

#LMS Digital Signature Algorithm Overview {#overview}

This specification makes use of the hash-based signature algorithm
specified in {{HASHSIG}}, which is the Leighton and Micali adaptation
{{LM}} of the original Lamport-Diffie-Winternitz-Merkle one-time
signature system {{M1979}}{{M1987}}{{M1989a}}{{M1989b}}.
   
The hash-based signature algorithm has three major components:

~~~
   o  Hierarchical Signature System (HSS) -- see Section 2.1;

   o  Leighton-Micali Signature (LMS) -- see Section 2.2; and

   o  Leighton-Micali One-time Signature Algorithm (LM-OTS) -- see
         Section 2.3.
~~~

As implied by the name, the hash-based signature algorithm depends on
a collision-resistant hash function.  The the hash-based signature
algorithm specified in {{HASHSIG}} currently makes use of the SHA-256
one-way hash function {{SHS}}, but it also establishes an IANA registry
to permit the registration of additional one-way hash functions in the
future.

##Hierarchical Signature System (HSS) {#hss}

The hash-based signature algorithm specified in {{HASHSIG}} uses a
hierarchy of trees.  The Hierarchical N-time Signature System (HSS)
allows subordinate trees to be generated when needed by the
signer.  Otherwise, generation of the entire tree might take
weeks or longer.

An HSS signature as specified in {{HASHSIG}} carries the number of
signed public keys (Nspk), followed by that number of signed public keys,
followed by the LMS signature as described in {{lms}}.  The public key
for the top-most LMS tree is the public key of the HSS system.  The LMS
private key in the parent tree signs the LMS public key in the child
tree, and the LMS private key in the bottom-most tree signs the actual
message.  The signature over the public key and the signature over the
actual message are LMS signatures as described in {{lms}}.

The elements of the HSS signature value for a stand-alone tree (a top
tree with no children) can be summarized as:

~~~
   u32str(0) ||
   lms_signature  /* signature of message */
~~~

The elements of the HSS signature value for a tree with Nspk signed public
keys can be summarized as:

~~~
   u32str(Nspk) ||
   signed_public_key[0] ||
   signed_public_key[1] ||
      ...
   signed_public_key[Nspk-2] ||
   signed_public_key[Nspk-1] ||
   lms_signature  /* signature of message */
~~~

where, as defined in Section 3.3 of {{HASHSIG}}, a signed_public_key is
the lms_signature over the public key followed by the public key
itself.  Note that Nspk is the number of levels in the hierarchy of
trees minus 1.

##Leighton-Micali Signature (LMS) {#lms}

Each tree in the hash-based signature algorithm specified in
{{HASHSIG}} uses the Leighton-Micali Signature (LMS) system.  LMS
systems have two parameters.  The first parameter is the height of
the tree, h, which is the number of levels in the tree minus one.
The {{HASHSIG}} includes support for five values of this
parameter: h=5; h=10; h=15; h=20; and h=25.  Note that there are 2^h
leaves in the tree.  The second parameter is the number of bytes
output by the hash function, m, which is the amount of data
associated with each node in the tree.  This specification supports
only SHA-256, with m=32.  An IANA registry is defined so that other
hash functions could be used in the future.

The {{HASHSIG}} specification supports five tree sizes:

~~~
   LMS_SHA256_M32_H5;
   LMS_SHA256_M32_H10;
   LMS_SHA256_M32_H15;
   LMS_SHA256_M32_H20; and
   LMS_SHA256_M32_H25.
~~~

The {{HASHSIG}} specification  establishes an IANA registry to permit
the registration of additional hash functions and additional tree
sizes in the future.

The LMS public key can be summarized as:

~~~
   u32str(lms_algorithm_type) || u32str(otstype) || I || T[1]
~~~

An LMS signature consists of four elements: the number of the leaf
associated with the LM-OTS signature, an LM-OTS signature as
described in {{lmots}}, a typecode indicating the particular LMS
algorithm, and an array of values that is associated with the path
through the tree from the leaf associated with the LM-OTS signature
to the root.  The array of values contains the siblings of the nodes
on the path from the leaf to the root but does not contain the nodes
on the path itself.  The array for a tree with height h will have h
values.  The first value is the sibling of the leaf, the next value
is the sibling of the parent of the leaf, and so on up the path to
the root.

The four elements of the LMS signature value can be summarized as:

~~~
   u32str(q) ||
   ots_signature ||
   u32str(type) ||
   path[0] || path[1] || ... || path[h-1]
~~~

##Leighton-Micali One-time Signature Algorithm (LM-OTS) {#lmots}

The hash-based signature algorithm depends on a one-time signature
method.  This specification makes use of the Leighton-Micali One-time
Signature Algorithm (LM-OTS) {{HASHSIG}}.  An LM-OTS has five
parameters:

~~~
   n -  The number of bytes output by the hash function.  This
        specification supports only SHA-256 [SHS], with n=32.

   H -  A preimage-resistant hash function that accepts byte strings
        of any length, and returns an n-byte string.  This
        specification supports only SHA-256 [SHS].

   w -  The width in bits of the Winternitz coefficients.  [HASHSIG]
        supports four values for this parameter: w=1; w=2; w=4; and
        w=8.

   p -  The number of n-byte string elements that make up the LM-OTS
        signature.

   ls - The number of left-shift bits used in the checksum function,
        which is defined in Section 4.5 of [HASHSIG].
~~~

The values of p and ls are dependent on the choices of the parameters
n and w, as described in Appendix A of {{HASHSIG}}.

The {{HASHSIG}} specification supports four LM-OTS variants:

~~~
   LMOTS_SHA256_N32_W1;
   LMOTS_SHA256_N32_W2;
   LMOTS_SHA256_N32_W4; and
   LMOTS_SHA256_N32_W8.
~~~

The {{HASHSIG}} specification  establishes an IANA registry to permit
the registration of additional hash functions and additional parameter
sets in the future.

Signing involves the generation of C, which is an n-byte random value.

The LM-OTS signature value can be summarized as:

~~~
   u32str(otstype) || C || y[0] || ... || y[p-1]
~~~

#Hash-based Signature Algorithm Identifiers {#algids}

The CBOR Object Signing and Encryption (COSE) {{RFC8152}} supports two
signature algorithm schemes.  This specification makes use of the
signature with appendix scheme for hash-based signatures.

The signature value is a large byte string.  The byte string is
designed for easy parsing, and it includes a counter and type codes
that indirectly provide all of the information that is needed to
parse the byte string during signature validation.

When using a COSE key for this algorithm, the following checks are made:

~~~
   o  The 'kty' field MUST be present, and it MUST be 'HSS-LMS'.

   o  If the 'alg' field is present, and it MUST be 'HSS-LMS'.

   o  If the 'key_ops' field is present, it MUST include 'sign' when
        creating a hash-based signature.

   o  If the 'key_ops' field is present, it MUST include 'verify'
        when verifying a hash-based signature.

   o  If the 'kid' field is present, it MAY be used to identify the
        top of the HSS tree.  In [HASHSIG], this identifier is called
        'I', and it is the 16-byte identifier of the LMS public key
        for the tree.
~~~

#Security Considerations {#seccons}

##Implementation Security Considerations

Implementations must protect the private keys.  Use of a hardware
security module (HSM) is one way to protect the private keys.
Compromise of the private keys may result in the ability to forge
signatures.  Along with the private key, the implementation must keep
track of which leaf nodes in the tree have been used.  Loss of
integrity of this tracking data can cause a one-time key to be used
more than once.  As a result, when a private key and the tracking
data are stored on non-volatile media or stored in a virtual machine
environment, care must be taken to preserve confidentiality and
integrity.

When a LMS key pair is generating a LMS key pair, an implementation
must must generate the key pair and the corresponding identifier
independently of all other key pairs in the HSS tree.

An implementation must ensure that a LM-OTS private key is used to
generate a signature only one time, and ensure that it cannot be used
for any other purpose.

The generation of private keys relies on random numbers.  The use of
inadequate pseudo-random number generators (PRNGs) to generate these
values can result in little or no security.  An attacker may find it
much easier to reproduce the PRNG environment that produced the keys,
searching the resulting small set of possibilities, rather than brute
force searching the whole key space.  The generation of quality
random numbers is difficult.  {{RFC4086}} offers important guidance in
this area.

The generation of hash-based signatures also depends on random
numbers.  While the consequences of an inadequate pseudo-random
number generator (PRNGs) to generate these values is much less severe
than the generation of private keys, the guidance in {{RFC4086}}
remains important.

#Operational Considerations {#opcons}

The public key for the hash-based signature is the key at the root of
Hierarchical Signature System (HSS).  In the absence of a public key
infrastructure {{RFC5280}}, this public key is a trust anchor, and the
number of signatures that can be generated is bounded by the size of
the overall HSS set of trees.  When all of the LM-OTS signatures have
been used to produce a signature, then the establishment of a new
trust anchor is required.

To ensure that none of tree nodes are used to generate more than one
signature, the signer maintains state across different invocations of
the signing algorithm.  Section 12.2 of [HASHSIG] offers some
practical implementation approaches around this statefulness.  In
some of these approaches, nodes are sacrificed to ensure that none
are used more than once.  As a result, the total number of signatures
that can be generated might be less than the overall HSS set of trees.

#IANA Considerations {#iana}

IANA is requested to add entries for hash-based signatures in the
"COSE Algorithms" registry and hash-based public keys in the "COSE
Key Types" registry.

##COSE Algorithms Registry Entry

The new entry in the "COSE Algorithms" registry has the following columns:

~~~
   Name:  HSS-LMS
   
   Value:  TBD (Value to be assigned by IANA)

   Description:  HSS/LMS hash-based digital signature

   Reference:  This document (Number to be assigned by RFC Editor)

   Recommended:  Yes
~~~

##COSE Key Types Registry Entry

The new entry in the "COSE Key Types" registry has the following columns:

~~~
   Name:  HSS-LMS

   Value:  TBD (Value to be assigned by IANA)

   Description:  Public key for HSS/LMS hash-based digital signature

   Reference:  This document (Number to be assigned by RFC Editor)
~~~

--- back

#Examples

This appendix provides an example of a COSE full message signature and
an example of a COSE_Sign0 message.

The programs that were used to generate the examples can be found at
https://github.com/cose-wg/Examples.

##Example COSE Full Message Signature

This section provides an example of a COSE full message signature.

~~~
{
   "title":"HSS LMS Hash based signature - hsssig-01",
   "input":{
      "plaintext":"This is the content.",
      "sign":{
         "protected":{
            "ctyp":0
         },
         "signers":[
            {
               "key":{
                  "kty":"HSS-LMS",
                  "kid":"ItsBig",
                  "comment":"1 level key - LM_SHA256_MD32_H10 + \
                      LMOTS_SHA256_N32_W4 ",
                  "public":"000000010000000600000003d08fabd4a20 \
                      91ff0a8cb4ed834e7453432a58885cd9ba0431235 \
                      466bff9651c6c92124404d45fa53cf161c28f1ad5a8e",
                  "private":"1|6|3|558B8966C48AE9CB898B423C8344 \
                      3AAE014A72F1B1AB5CC85CF1D892903B5439|1|d0 \
                      8fabd4a2091ff0a8cb4ed834e74534"
               },
               "unprotected":{
                  "kid":"ItsBig"
               },
               "protected":{
                  "alg":"HSS-LMS"
               }
            }
         ]
      },
      "rng_description":"Random value for signature",
      "rng_stream":[
         "ACFC5C7377D45C969DF7D7289882A48C1A10E5C48B6E29DF5018D \
             3E683E36BC5"
      ]
   },
   "intermediates":{
      "signers":[
         {
            "ToBeSign_hex":"85695369676E617475726543A103004AA10 \
                1674853532D4C4D53405454686973206973207468652063 \
                6F6E74656E742E"
         }
      ]
   },
   "output":{
      "cbor_diag":"98([h'A10300', {}, h'54686973206973207468652 \
          0636F6E74656E742E', [[h'A101674853532D4C4D53', \
          {4: h'497473426967'}, h'00000000000000010000000391291 \
          DE76CE6E24D1E2A9B60266519BC8CE889F814DEB0FC00EDD3129D \
          E3AB9BFC0F5DA46923923AA3209BF9E1480AB78906D79D4C9280A \
          DC6300C182CB33429CE0035FE3E2E4428770D22F85687A18AEE76 \
          CDC2F8E8F40043B314A68E72F9F679F7E3A5A34594E7673EEB70E \
          840FBFFDA398EC59BF0236FDD34ACE319DC1EAD1BD22B0213A094 \
          6160F30168A6E193C57C32BB017C22529EC3760FF93358633D5A6 \
          9F7F0850BD720E72FF758B19D4E27D114B1E6321BFDF1859102E7 \
          23A3B1F1AE5BC53EC8732FF1B2C4D384137E8EEEC94804CB47C82 \
          3C0B01441E28B178E1F5A904CF7592AAACF820C97E7714B69FCA4 \
          BABE97854B0C00A705CAE7BA9112D182C21BCE3F10EA70C324F46 \
          6749279610A3477B03E3622169438C27CD46FCAD769D010D0B13A \
          06F5CD00D93A2EEB2BB0E25BFFD2A08C8DDF0653518B7BFEDB3B4 \
          6EB56BDA75B0421DF87F7FD1F08808B58DD3647472D90F8F9459C \
          775BFF5930956EBD7BF4D5F6B26BC53196FF9B660949B23154B9C \
          E7A0DF55E9083B42A90D82F8D1DE2F62770EBDCE42A4A50448854 \
          15C7BA81EFED2BCF8C1B6932215646E9EF160DDD79CA4DD6F4774 \
          85BB5B01AAD4DF4D6D45942B935C74D35BD340D9D83CBC8F8A719 \
          D6BB5CE098091C8787E193C84CE386355C55807A17CE1BFF830D4 \
          B87D63646EF8FC1E9E9071BB67A123FDEC3F37638CDAF0F4BF308 \
          4074069171C10C4670163B9626635ADE3BD6D7917D0B029C7D4B8 \
          8B005473B6FF3862FB491CD1E1F6069B306C4EF8AE4C7F83EB320 \
          A20406AA7FFF84BFDD22AD876B4661ED5D38F35591625F1D53DC1 \
          BD472D1B4D93E93DA31A8CD5CEA70B6DD7BCFA510E5BD31C1AA60 \
          BD252071D689C9D9CC1EDFE8AA0235C654F758FC8936515AE3441 \
          C3B9F2AFFA164AF2999C6994C54F0AC923F0E6ED8C48C6148234E \
          ADB87ABEA3C935B3D9682E6D121506131E6928474327E1E47CE7C \
          9D9BD4C36E7A274664B21B1E6304CCD6111E53159775196AAC4D5 \
          9ED5FF553F4EC9597DF17873BB5E47827D83AA48BD22849D5A97C \
          93A106672BDEB52ED7B6D2C56CE32700513C0FC04F26549A6FC5C \
          DBB5634C0BFBB6EF1FAADA66923D21BAB3BF62C6DD6D7DAAB67AB \
          A8923C4CF1CC8ABB47F33DF12617C38A7B1DB13E6B2D6E23DFA59 \
          F8E760966B7B17A5B492C6AE25920E8F697F7666D02222CD48852 \
          7DB55DAABD2F82D927BBB7EC06B833D4BBE08680A54B1E062D938 \
          8530B1F96696F712457AF44705400D8F443FAFB01D76FD6075D20 \
          845044ACCEA54DC4872A97C2DBCF0A9968001CB7C22F9D9387A76 \
          630FE4A825AA4054A3E5BA1486F5AD7B2A87FD4B248DCEE4E6EC1 \
          A2B8A2D2BFB19A74CA3027338633B18865EB5A16997D2DD3BC441 \
          35E47220182BC1FB7445037C3524641CF69370D0627C04C43A14E \
          778BADCFD7961551A9FCB95A8D4162A94110BC703F5F49CB85322 \
          CA9007322F2DBE55DC237FAED2FBF9C953EF9F5EBBDC0058BFD69 \
          475A87D32E4A9E5C266012B0CCE1E507AD10FC01D7E00FBF5556E \
          A9DC716B812357F0BE844FD14C33C582E80EB1603D78C00A6E9F6 \
          7EB8981A04581122F3F0DDCF997F6F7CB637857C07DEC7353DA14 \
          03BAAFAC8DB374922198081D77F52DB3F8B6281471D53BB11C6DA \
          56DD733632021F584E207FD61222C4FFEFAA74214C7634B6171C9 \
          5905CA05D9A3A686A7BA541BFA59A76F9CB85F4A5272BC6209A41 \
          CF83A22EF22074B2760118952B8282ACEF179B26C879D2C8B4238 \
          979E4BD512D8A5D20578810E134F254B4C1D22685B58537632259 \
          BB6B4CC14FB6E6C94C1087441A81F11B9A83535B24DDC725A81A9 \
          D1FF62DA2804C8D84C6E3837D97DEF03AA275D348E7C0AA4A46A3 \
          9EDDDD55C45513AB692BD7DEC0F0B142F3E7075CBEA436F3791AF \
          2C6E014F73C8A29464393BBB56ACE6A7048F1E444934125C9B5F7 \
          8A5AA130F238A441DBEC5EA73F61D00D059CB2A137D6F9EC27306 \
          8B2545549E525055CDE70F7C7C28FB4CADC251AE6FE3186DF1987 \
          0661831E95C76450146654A3D36184CFFAA1EFC684ACD21D2498E \
          298FD18E99D5C6AFAF5588CCDDC2475B9E8294677924FA8283094 \
          810F7DD9FEF57DFF359805725ED044AC13D1794D7949FE0EAFC42 \
          5933A7D788035C6C825A580EC3E26F7B3BE31FB98A7F67BCC6FF5 \
          1ABEA2A7D9FF6D898018B5FBEE74D892C8694101236E20991499D \
          0385A18B290BCF2938806D602E27800C21B2E38C65B987B10D360 \
          B2C674EED6A6205F251A0E68B7D57060DE5E3F599BA197997EE49 \
          DA7D6AB97119F03AF737CE914B004462AA07C61B15311BBA10FC5 \
          BB68A2621E47BE3374222DFFDE29C7910418F6D9E4DD1B7B7A9B3 \
          600689019F188EA696B7951A10C15E9BD01A5160E1A571942E223 \
          C6F29A70528E5CF7A52F1F60806A9FF729E76D69BFD315383F031 \
          C3863650757F1EF75D474935147FBAA9A6DA0ABF7C5BCF4E05026 \
          FD134AC20815A3A81A026213EA50FF1454F2399518DD359D49D9E \
          475DA432FFD4B953875FDB7A7EA7D04AC13D4102851D90BAB6527 \
          72527E85C485E863D9A1AC76BC0474D53FA5E6A77E64210788FBD \
          EB5696C6DEEEDF18AAC2BC74FC861AB770175A032273E4D5D7366 \
          C8FFE6F446995B564FC3D59C70FECDB60A25E28650417157F43F3 \
          E72C3AFC2372EC9D0787CB37BFAC383648E7A168EAACCA7C55505 \
          F93E9A09310320CB5184512F583F2FEA5853C36E6E43A6E6BE182 \
          185F04FE4B05170865618A51CF25542EADF473D5794295BDC86FC \
          6909D301E952346E32D69320D333BCA39B4FF8AF7E199BD55D919 \
          0F1FED4D3225274F03A1806E201ED2D040509FD7FA67C9CE6068E \
          C54B56D53BF47E67B5B8B6382A0CB69A61D7FBC2DDEDA171D4F70 \
          14262FC77F454A3E68E6EFB7C31C4080024C8027FD8D6CE648B78 \
          2B56B762BEE5ADA237D018689B58902CBAC4E44C931416B47CD5E \
          20026D5B81B407A0E29CAAEC81F1C3528463132F00589A9F8021A \
          74109F8DBF81FE282C1F58BF3F2A52C560E38BFD68B2D28679CBC \
          089F2C9C3FC245FF5FA3ADA7F7973D9BD4BEC69B1F0C71416A6C4 \
          F00000006ED1CE8C6E437918D43FBA7BD9385694C41182703F6B7 \
          F704DEEDD9384BA6F8BC362C948646B3C9848803E6D9BA1F7D396 \
          7F709CDDD35DC77D60356F0C36808900B491CB4ECBBABEC128E7C \
          81A46E62A67B57640A0A78BE1CBF7DD9D419A10CD8686D16621A8 \
          0816BFDB5BDC56211D72CA70B81F1117D129529A7570CF79CF52A \
          7028A48538ECDD3B38D3D5D62D26246595C4FB73A525A5ED2C305 \
          24EBB1D8CC82E0C19BC4977C6898FF95FD3D310B0BAE71696CEF9 \
          3C6A552456BF96E9D075E383BB7543C675842BAFBFC7CDB88483B \
          3276C29D4F0A341C2D406E40D4653B7E4D045851ACF6A0A0EA9C7 \
          10B805CCED4635EE8C107362F0FC8D80C14D0AC49C516703D26D1 \
          4752F34C1C0D2C4247581C18C2CF4DE48E9CE949BE7C888E9CAEB \
          E4A415E291FD107D21DC1F084B1158208249F28F4F7C7E931BA7B \
          3BD0D824A4570']]])",
      "cbor":"D8628443A10300A054546869732069732074686520636F6E7 \
          4656E742E81834AA101674853532D4C4D53A10446497473426967 \
          5909D000000000000000010000000391291DE76CE6E24D1E2A9B6 \
          0266519BC8CE889F814DEB0FC00EDD3129DE3AB9BFC0F5DA46923 \
          923AA3209BF9E1480AB78906D79D4C9280ADC6300C182CB33429C \
          E0035FE3E2E4428770D22F85687A18AEE76CDC2F8E8F40043B314 \
          A68E72F9F679F7E3A5A34594E7673EEB70E840FBFFDA398EC59BF \
          0236FDD34ACE319DC1EAD1BD22B0213A0946160F30168A6E193C5 \
          7C32BB017C22529EC3760FF93358633D5A69F7F0850BD720E72FF \
          758B19D4E27D114B1E6321BFDF1859102E723A3B1F1AE5BC53EC8 \
          732FF1B2C4D384137E8EEEC94804CB47C823C0B01441E28B178E1 \
          F5A904CF7592AAACF820C97E7714B69FCA4BABE97854B0C00A705 \
          CAE7BA9112D182C21BCE3F10EA70C324F466749279610A3477B03 \
          E3622169438C27CD46FCAD769D010D0B13A06F5CD00D93A2EEB2B \
          B0E25BFFD2A08C8DDF0653518B7BFEDB3B46EB56BDA75B0421DF8 \
          7F7FD1F08808B58DD3647472D90F8F9459C775BFF5930956EBD7B \
          F4D5F6B26BC53196FF9B660949B23154B9CE7A0DF55E9083B42A9 \
          0D82F8D1DE2F62770EBDCE42A4A5044885415C7BA81EFED2BCF8C \
          1B6932215646E9EF160DDD79CA4DD6F477485BB5B01AAD4DF4D6D \
          45942B935C74D35BD340D9D83CBC8F8A719D6BB5CE098091C8787 \
          E193C84CE386355C55807A17CE1BFF830D4B87D63646EF8FC1E9E \
          9071BB67A123FDEC3F37638CDAF0F4BF3084074069171C10C4670 \
          163B9626635ADE3BD6D7917D0B029C7D4B88B005473B6FF3862FB \
          491CD1E1F6069B306C4EF8AE4C7F83EB320A20406AA7FFF84BFDD \
          22AD876B4661ED5D38F35591625F1D53DC1BD472D1B4D93E93DA3 \
          1A8CD5CEA70B6DD7BCFA510E5BD31C1AA60BD252071D689C9D9CC \
          1EDFE8AA0235C654F758FC8936515AE3441C3B9F2AFFA164AF299 \
          9C6994C54F0AC923F0E6ED8C48C6148234EADB87ABEA3C935B3D9 \
          682E6D121506131E6928474327E1E47CE7C9D9BD4C36E7A274664 \
          B21B1E6304CCD6111E53159775196AAC4D59ED5FF553F4EC9597D \
          F17873BB5E47827D83AA48BD22849D5A97C93A106672BDEB52ED7 \
          B6D2C56CE32700513C0FC04F26549A6FC5CDBB5634C0BFBB6EF1F \
          AADA66923D21BAB3BF62C6DD6D7DAAB67ABA8923C4CF1CC8ABB47 \
          F33DF12617C38A7B1DB13E6B2D6E23DFA59F8E760966B7B17A5B4 \
          92C6AE25920E8F697F7666D02222CD488527DB55DAABD2F82D927 \
          BBB7EC06B833D4BBE08680A54B1E062D9388530B1F96696F71245 \
          7AF44705400D8F443FAFB01D76FD6075D20845044ACCEA54DC487 \
          2A97C2DBCF0A9968001CB7C22F9D9387A76630FE4A825AA4054A3 \
          E5BA1486F5AD7B2A87FD4B248DCEE4E6EC1A2B8A2D2BFB19A74CA \
          3027338633B18865EB5A16997D2DD3BC44135E47220182BC1FB74 \
          45037C3524641CF69370D0627C04C43A14E778BADCFD7961551A9 \
          FCB95A8D4162A94110BC703F5F49CB85322CA9007322F2DBE55DC \
          237FAED2FBF9C953EF9F5EBBDC0058BFD69475A87D32E4A9E5C26 \
          6012B0CCE1E507AD10FC01D7E00FBF5556EA9DC716B812357F0BE \
          844FD14C33C582E80EB1603D78C00A6E9F67EB8981A04581122F3 \
          F0DDCF997F6F7CB637857C07DEC7353DA1403BAAFAC8DB3749221 \
          98081D77F52DB3F8B6281471D53BB11C6DA56DD733632021F584E \
          207FD61222C4FFEFAA74214C7634B6171C95905CA05D9A3A686A7 \
          BA541BFA59A76F9CB85F4A5272BC6209A41CF83A22EF22074B276 \
          0118952B8282ACEF179B26C879D2C8B4238979E4BD512D8A5D205 \
          78810E134F254B4C1D22685B58537632259BB6B4CC14FB6E6C94C \
          1087441A81F11B9A83535B24DDC725A81A9D1FF62DA2804C8D84C \
          6E3837D97DEF03AA275D348E7C0AA4A46A39EDDDD55C45513AB69 \
          2BD7DEC0F0B142F3E7075CBEA436F3791AF2C6E014F73C8A29464 \
          393BBB56ACE6A7048F1E444934125C9B5F78A5AA130F238A441DB \
          EC5EA73F61D00D059CB2A137D6F9EC273068B2545549E525055CD \
          E70F7C7C28FB4CADC251AE6FE3186DF19870661831E95C7645014 \
          6654A3D36184CFFAA1EFC684ACD21D2498E298FD18E99D5C6AFAF \
          5588CCDDC2475B9E8294677924FA8283094810F7DD9FEF57DFF35 \
          9805725ED044AC13D1794D7949FE0EAFC425933A7D788035C6C82 \
          5A580EC3E26F7B3BE31FB98A7F67BCC6FF51ABEA2A7D9FF6D8980 \
          18B5FBEE74D892C8694101236E20991499D0385A18B290BCF2938 \
          806D602E27800C21B2E38C65B987B10D360B2C674EED6A6205F25 \
          1A0E68B7D57060DE5E3F599BA197997EE49DA7D6AB97119F03AF7 \
          37CE914B004462AA07C61B15311BBA10FC5BB68A2621E47BE3374 \
          222DFFDE29C7910418F6D9E4DD1B7B7A9B3600689019F188EA696 \
          B7951A10C15E9BD01A5160E1A571942E223C6F29A70528E5CF7A5 \
          2F1F60806A9FF729E76D69BFD315383F031C3863650757F1EF75D \
          474935147FBAA9A6DA0ABF7C5BCF4E05026FD134AC20815A3A81A \
          026213EA50FF1454F2399518DD359D49D9E475DA432FFD4B95387 \
          5FDB7A7EA7D04AC13D4102851D90BAB652772527E85C485E863D9 \
          A1AC76BC0474D53FA5E6A77E64210788FBDEB5696C6DEEEDF18AA \
          C2BC74FC861AB770175A032273E4D5D7366C8FFE6F446995B564F \
          C3D59C70FECDB60A25E28650417157F43F3E72C3AFC2372EC9D07 \
          87CB37BFAC383648E7A168EAACCA7C55505F93E9A09310320CB51 \
          84512F583F2FEA5853C36E6E43A6E6BE182185F04FE4B05170865 \
          618A51CF25542EADF473D5794295BDC86FC6909D301E952346E32 \
          D69320D333BCA39B4FF8AF7E199BD55D9190F1FED4D3225274F03 \
          A1806E201ED2D040509FD7FA67C9CE6068EC54B56D53BF47E67B5 \
          B8B6382A0CB69A61D7FBC2DDEDA171D4F7014262FC77F454A3E68 \
          E6EFB7C31C4080024C8027FD8D6CE648B782B56B762BEE5ADA237 \
          D018689B58902CBAC4E44C931416B47CD5E20026D5B81B407A0E2 \
          9CAAEC81F1C3528463132F00589A9F8021A74109F8DBF81FE282C \
          1F58BF3F2A52C560E38BFD68B2D28679CBC089F2C9C3FC245FF5F \
          A3ADA7F7973D9BD4BEC69B1F0C71416A6C4F00000006ED1CE8C6E \
          437918D43FBA7BD9385694C41182703F6B7F704DEEDD9384BA6F8 \
          BC362C948646B3C9848803E6D9BA1F7D3967F709CDDD35DC77D60 \
          356F0C36808900B491CB4ECBBABEC128E7C81A46E62A67B57640A \
          0A78BE1CBF7DD9D419A10CD8686D16621A80816BFDB5BDC56211D \
          72CA70B81F1117D129529A7570CF79CF52A7028A48538ECDD3B38 \
          D3D5D62D26246595C4FB73A525A5ED2C30524EBB1D8CC82E0C19B \
          C4977C6898FF95FD3D310B0BAE71696CEF93C6A552456BF96E9D0 \
          75E383BB7543C675842BAFBFC7CDB88483B3276C29D4F0A341C2D \
          406E40D4653B7E4D045851ACF6A0A0EA9C710B805CCED4635EE8C \
          107362F0FC8D80C14D0AC49C516703D26D14752F34C1C0D2C4247 \
          581C18C2CF4DE48E9CE949BE7C888E9CAEBE4A415E291FD107D21 \
          DC1F084B1158208249F28F4F7C7E931BA7B3BD0D824A4570"
   }
}
~~~

##Example COSE_Sign0 Message

This section provides an example of a COSE_Sign0 message.

~~~
{
   "title":"HSS LMS Hash based signature - hsssig-sig-01",
   "input":{
      "plaintext":"This is the content.",
      "sign0":{
         "key":{
            "kty":"HSS-LMS",
            "kid":"ItsBig",
            "comment":"1 level key - LM_SHA256_MD32_H10 + \
                LMOTS_SHA256_N32_W4 ",
            "public":"000000010000000600000003d08fabd4a2091ff0a \
                8cb4ed834e7453432a58885cd9ba0431235466bff9651c6 \
                c92124404d45fa53cf161c28f1ad5a8e",
            "private":"1|6|3|558B8966C48AE9CB898B423C83443AAE01 \
                4A72F1B1AB5CC85CF1D892903B5439|0|d08fabd4a2091f \
                f0a8cb4ed834e74534"
         },
         "unprotected":{
            "kid":"ItsBig"
         },
         "protected":{
            "alg":"HSS-LMS"
         },
         "alg":"HSS-LMS"
      },
      "rng_description":"Random value for signature",
      "rng_stream":[
         "1D5112D38A1146402875B73BC8D4B59C845C6AE61D03A70ABAD09 \
         8AC05AD8297"
      ]
   },
   "intermediates":{
      "ToBeSign_hex":"846A5369676E6174757265314AA101674853532D4 \
      C4D534054546869732069732074686520636F6E74656E742E"
   },
   "output":{
      "cbor_diag":"18([h'A101674853532D4C4D53', \
          {4: h'497473426967'}, \
          h'546869732069732074686520636F6E74656E742E', \
          h'00000000000000000000000391291DE76CE6E24D1E2A9B60266 \
          519BC8CE889F814DEB0FC00EDD3129DE3AB9BA6814A4BEE84E5E8 \
          38C7725F78FE0610837A548F92802DA610AFB0ADFB133123061C0 \
          23E87A7802C17B00740F25737A775B95E923905B6F0CA02A87095 \
          5420A68003133A1EA12083E134238DFE5F1633E159CFD207BC79B \
          50DD39BA39FCAAA75C12F7F1B493AB8736162E42C2C2F9159DF33 \
          32C399A50BB8404F2CB6D98DAA4C3DF82A197CFE014BEC27CC820 \
          A5B26BAC5DFE05947E3A7D92070A4653C67BA095AB0499AF655B8 \
          1B719912E296765FA46CB0AD2ED56BBCF00CA6FB9C16D8C05C1C1 \
          65FED054A099A3DA89F9CB951C6ED366DF38E299C7E7DC9AC9C43 \
          66F328407E7C4A6CD8A5314D6B02B377406D5A5E589E91FEAA9F2 \
          E4EC1682BA1F633C7784B3038FAC2E77947916C8F4160CF6D9D0B \
          0BC6600CDBC4AE947DD5D317DCBA3D200A739F96CDDBA94DAF86C \
          E80C76158D4F5CF3CD2BA9F1393DF47E556887F919E0718625D31 \
          240E7FE9599012F757314C20893827194AD6555F1452E3A749CE2 \
          13DFBA283013DCFF196F9BD18D715B6E7451DE35B18181DF8A626 \
          DE1480F2DDECB126B477E019FFE75E4472EF4FA1B913C80821155 \
          AAE0D7F3B1175B64CA076926166C80E8219D241791C1DE3C8F936 \
          55085C0B00F840970367DAF2A41D462C696C74AF0C3591A6C6B4D \
          701963819FFBDC945785D64CE687BA4D086A31FE6A5E1C74A6C0E \
          25CF67CEA24DCDE0E47B5210670CC2D66003DF2232F4BA337D325 \
          166381681FD4738997BB3EC1499E594B5CCE9FBC11C3136C20F15 \
          6012A4DA062675627758DBF1BE635C876F81713D322EA127F6FFC \
          8880F42BA51879CC0EB27B8A0C21E434DA7C490BFE30BE1FAC3CA \
          A5CF97451FADF412ECA7BAD72E2553541224EB934A9C8A0034E1C \
          59EA2D9EAFD66A72F1C43A07B70CBBC0AD844506E31C4CC84F395 \
          F28915239C8CB733787EE79704B8BA0CC667282984DFBD01BDC34 \
          ADF0E90A309986BE6AD95486E67754543999AEE160A7C6458992F \
          ABC338136D95FBC688E0F4F03D8F942875DF39E8D9EAA6B35FFA6 \
          C9C1097E5BEA8EADA90DAAC52FBE16A830EA49D550ABFFB64C824 \
          4095992BAE73D970AE908CE9413A6EC52F98F593E138F3E6B7BAE \
          A6657E03DF715516DD69342374D222F9A4D4B6579994DD01F4E7E \
          C1C254C2A5EA109519C788FA1504B0273975C3E647820CFE5CDF4 \
          D0D5A6C717C1795EB2BE37030EDEB3196D5866255B1FC10BD03B0 \
          5FBDF59DBD87451877761BDEDD25D468D9409A054B1767BF70C41 \
          61D416B01F472E4D0924FB9EF84A7EF027A4C3F6FDDD0018A827A \
          B66017062F0F0709B271C1CB03557558F882C4FD89569E55E86D9 \
          834105F5E7468BA389305729F7FEB6BF2BE3F92BCA40917CC947A \
          438B43D6A109535EEBFC06BAEE3A01C9E49D95E84ACDA572F47C4 \
          FECC648903154182BBF5222CD4F40622DBB6886A062FE52A59260 \
          EC8B61843622DA827B77BAFB0E0F7AA55E3E869BD7943C780F317 \
          82241FE1D8B55C313A421875EFE40BD3B649087AE3A1A5942A51A \
          7C182EDF686A9842A2F82E51ABE70826D5CA045F984472DB63784 \
          194DC2C523889A95CA8C625B017BCA6CAC5175E87552EACBD8D3F \
          5C281E4D4108F90E395088D50C528809C37788609A5734FFCE402 \
          87270A3A6B04A069DE8277F7F5109C16938347A643713C9AC36FF \
          FC8BF141E899F48BC25C7B636D43BEBCFA7742D4E1462263E5673 \
          2AD2021EEF8CE84023C4959CFD250348B23AE6DB317087F1F593F \
          768825A970E85C15306447892E72C8CF4461E3DF57E696AF1780A \
          DA04F847F8FD3C42A802FC9BA38C696ED74FF8A300D171BBAE888 \
          8B226498CF63EBA035814557E3A552E0B5DA56DD90C1372D82386 \
          0D00CA4F242E8BF1FCA88BA71173DE185E6F1D1EF2BAE53D701D0 \
          3D4BF3B44F0842BED8126494A7FD2C7B1321A5527B78681B1D130 \
          62CE4DAE86C68DAB481551D857934250E6DBF99D37DA15735831C \
          2FA31DD2AB81FBF1F2DE8D890DF29A8CCD730431135E3A0D9C075 \
          860F9843B14BE9408714E96218D3642E5B0126BD8FF941757A512 \
          CDCB4F6336D6FDC357C28E59484EDC9101AE78BBC6CB380E6E051 \
          6ECC48391FE9DA4519DF813CB680497BA65132954F11F857BDFF3 \
          644B7F54F59542BAE97EBC7270DECDD407989CAD427894922EDC1 \
          BD22E5E1991E1B894A92F893268F66327084B09A945732EF82F27 \
          007D5DD0A08403E8E553EA7E20C1E23A567B850F8FE4D00417099 \
          5CE1FCC2284EACB197F001C9B0FF2FB67BC24C5774A935F96761F \
          D52394AEDE47896E5204BD011F2697F9791953C0F265909019A90 \
          804A3A59A4D5A481020861ADC270845EBEE08D8C5C442A0ECBB5C \
          78D65E11A5CD71D520281A73C8EE741B4B1E2807E30BD9A2AD1DF \
          E50FE3875F201926D87F732461E279FB774E97A93363527C13948 \
          DBE1776B7FB8604762C576402481704E4E056D67F00EC4399CED2 \
          B8802C89A78827B12FDC5D8B8A3A1914A80B573D3C4F3C87E91AE \
          3DBB05B685CEC2194604FA3965B0AF4E0D6E929D672E6C2EDC600 \
          1FC2A9AB1CA244FD07847B86A544AAB532DD2E49C2ACB9C42330B \
          44F95AEF50A1E44761E5E25670DA2C7291254C17C298F685B1FB0 \
          22932B07DE031B1E9988131C73BD0B4E748FF2C2FFD45B7DF99EF \
          1FA579F02930D3C3AA3D46F50AF699CF3E5E11E035B693542EBB5 \
          B7D756B001BA792C8B6F4521A4F49DB647A37095A28482548E3C0 \
          E9DFB0C2D504BE2E9B60983660B05E45FF8847BD7392ED1010AA8 \
          5589B36455B864A682B58A87CE0BE617C838BEA0295186178B1EC \
          2CD64044B8FF4A30FFEFAE2A007E7531250E0EBBB76621CBECF25 \
          5E08727BBE61178A3CF25395468F207249A97EF9A631D9CD651FD \
          36ADC2CB00B81663E6C89869E7C2BCB6C149E9CA97B4AC8F656F9 \
          B54A800C81045C77A6DD75040AFB72273F1C1A2B8A0E60E60F5FA \
          9C63AA4DBBCE603BBAF99DE4EB95FED967E444FABD025D40A2D74 \
          AFE0AD427C5E0D5DDFE3267DD04256752FB643D362E8DA17B5E44 \
          81A45176376804FF489DF09FDA863BD4000000067B95DE445ABF8 \
          9161DFF4B91A4A9E3BF156A39A4660F98F06BF3F017686D9DFC36 \
          2C948646B3C9848803E6D9BA1F7D3967F709CDDD35DC77D60356F \
          0C36808900B491CB4ECBBABEC128E7C81A46E62A67B57640A0A78 \
          BE1CBF7DD9D419A10CD8686D16621A80816BFDB5BDC56211D72CA \
          70B81F1117D129529A7570CF79CF52A7028A48538ECDD3B38D3D5 \
          D62D26246595C4FB73A525A5ED2C30524EBB1D8CC82E0C19BC497 \
          7C6898FF95FD3D310B0BAE71696CEF93C6A552456BF96E9D075E3 \
          83BB7543C675842BAFBFC7CDB88483B3276C29D4F0A341C2D406E \
          40D4653B7E4D045851ACF6A0A0EA9C710B805CCED4635EE8C1073 \
          62F0FC8D80C14D0AC49C516703D26D14752F34C1C0D2C4247581C \
          18C2CF4DE48E9CE949BE7C888E9CAEBE4A415E291FD107D21DC1F \
          084B1158208249F28F4F7C7E931BA7B3BD0D824A4570'])",
      "cbor":"D2844AA101674853532D4C4D53A1044649747342696754546 \
          869732069732074686520636F6E74656E742E5909D00000000000 \
          0000000000000391291DE76CE6E24D1E2A9B60266519BC8CE889F \
          814DEB0FC00EDD3129DE3AB9BA6814A4BEE84E5E838C7725F78FE \
          0610837A548F92802DA610AFB0ADFB133123061C023E87A7802C1 \
          7B00740F25737A775B95E923905B6F0CA02A870955420A6800313 \
          3A1EA12083E134238DFE5F1633E159CFD207BC79B50DD39BA39FC \
          AAA75C12F7F1B493AB8736162E42C2C2F9159DF3332C399A50BB8 \
          404F2CB6D98DAA4C3DF82A197CFE014BEC27CC820A5B26BAC5DFE \
          05947E3A7D92070A4653C67BA095AB0499AF655B81B719912E296 \
          765FA46CB0AD2ED56BBCF00CA6FB9C16D8C05C1C165FED054A099 \
          A3DA89F9CB951C6ED366DF38E299C7E7DC9AC9C4366F328407E7C \
          4A6CD8A5314D6B02B377406D5A5E589E91FEAA9F2E4EC1682BA1F \
          633C7784B3038FAC2E77947916C8F4160CF6D9D0B0BC6600CDBC4 \
          AE947DD5D317DCBA3D200A739F96CDDBA94DAF86CE80C76158D4F \
          5CF3CD2BA9F1393DF47E556887F919E0718625D31240E7FE95990 \
          12F757314C20893827194AD6555F1452E3A749CE213DFBA283013 \
          DCFF196F9BD18D715B6E7451DE35B18181DF8A626DE1480F2DDEC \
          B126B477E019FFE75E4472EF4FA1B913C80821155AAE0D7F3B117 \
          5B64CA076926166C80E8219D241791C1DE3C8F93655085C0B00F8 \
          40970367DAF2A41D462C696C74AF0C3591A6C6B4D701963819FFB \
          DC945785D64CE687BA4D086A31FE6A5E1C74A6C0E25CF67CEA24D \
          CDE0E47B5210670CC2D66003DF2232F4BA337D325166381681FD4 \
          738997BB3EC1499E594B5CCE9FBC11C3136C20F156012A4DA0626 \
          75627758DBF1BE635C876F81713D322EA127F6FFC8880F42BA518 \
          79CC0EB27B8A0C21E434DA7C490BFE30BE1FAC3CAA5CF97451FAD \
          F412ECA7BAD72E2553541224EB934A9C8A0034E1C59EA2D9EAFD6 \
          6A72F1C43A07B70CBBC0AD844506E31C4CC84F395F28915239C8C \
          B733787EE79704B8BA0CC667282984DFBD01BDC34ADF0E90A3099 \
          86BE6AD95486E67754543999AEE160A7C6458992FABC338136D95 \
          FBC688E0F4F03D8F942875DF39E8D9EAA6B35FFA6C9C1097E5BEA \
          8EADA90DAAC52FBE16A830EA49D550ABFFB64C8244095992BAE73 \
          D970AE908CE9413A6EC52F98F593E138F3E6B7BAEA6657E03DF71 \
          5516DD69342374D222F9A4D4B6579994DD01F4E7EC1C254C2A5EA \
          109519C788FA1504B0273975C3E647820CFE5CDF4D0D5A6C717C1 \
          795EB2BE37030EDEB3196D5866255B1FC10BD03B05FBDF59DBD87 \
          451877761BDEDD25D468D9409A054B1767BF70C4161D416B01F47 \
          2E4D0924FB9EF84A7EF027A4C3F6FDDD0018A827AB66017062F0F \
          0709B271C1CB03557558F882C4FD89569E55E86D9834105F5E746 \
          8BA389305729F7FEB6BF2BE3F92BCA40917CC947A438B43D6A109 \
          535EEBFC06BAEE3A01C9E49D95E84ACDA572F47C4FECC64890315 \
          4182BBF5222CD4F40622DBB6886A062FE52A59260EC8B61843622 \
          DA827B77BAFB0E0F7AA55E3E869BD7943C780F31782241FE1D8B5 \
          5C313A421875EFE40BD3B649087AE3A1A5942A51A7C182EDF686A \
          9842A2F82E51ABE70826D5CA045F984472DB63784194DC2C52388 \
          9A95CA8C625B017BCA6CAC5175E87552EACBD8D3F5C281E4D4108 \
          F90E395088D50C528809C37788609A5734FFCE40287270A3A6B04 \
          A069DE8277F7F5109C16938347A643713C9AC36FFFC8BF141E899 \
          F48BC25C7B636D43BEBCFA7742D4E1462263E56732AD2021EEF8C \
          E84023C4959CFD250348B23AE6DB317087F1F593F768825A970E8 \
          5C15306447892E72C8CF4461E3DF57E696AF1780ADA04F847F8FD \
          3C42A802FC9BA38C696ED74FF8A300D171BBAE8888B226498CF63 \
          EBA035814557E3A552E0B5DA56DD90C1372D823860D00CA4F242E \
          8BF1FCA88BA71173DE185E6F1D1EF2BAE53D701D03D4BF3B44F08 \
          42BED8126494A7FD2C7B1321A5527B78681B1D13062CE4DAE86C6 \
          8DAB481551D857934250E6DBF99D37DA15735831C2FA31DD2AB81 \
          FBF1F2DE8D890DF29A8CCD730431135E3A0D9C075860F9843B14B \
          E9408714E96218D3642E5B0126BD8FF941757A512CDCB4F6336D6 \
          FDC357C28E59484EDC9101AE78BBC6CB380E6E0516ECC48391FE9 \
          DA4519DF813CB680497BA65132954F11F857BDFF3644B7F54F595 \
          42BAE97EBC7270DECDD407989CAD427894922EDC1BD22E5E1991E \
          1B894A92F893268F66327084B09A945732EF82F27007D5DD0A084 \
          03E8E553EA7E20C1E23A567B850F8FE4D004170995CE1FCC2284E \
          ACB197F001C9B0FF2FB67BC24C5774A935F96761FD52394AEDE47 \
          896E5204BD011F2697F9791953C0F265909019A90804A3A59A4D5 \
          A481020861ADC270845EBEE08D8C5C442A0ECBB5C78D65E11A5CD \
          71D520281A73C8EE741B4B1E2807E30BD9A2AD1DFE50FE3875F20 \
          1926D87F732461E279FB774E97A93363527C13948DBE1776B7FB8 \
          604762C576402481704E4E056D67F00EC4399CED2B8802C89A788 \
          27B12FDC5D8B8A3A1914A80B573D3C4F3C87E91AE3DBB05B685CE \
          C2194604FA3965B0AF4E0D6E929D672E6C2EDC6001FC2A9AB1CA2 \
          44FD07847B86A544AAB532DD2E49C2ACB9C42330B44F95AEF50A1 \
          E44761E5E25670DA2C7291254C17C298F685B1FB022932B07DE03 \
          1B1E9988131C73BD0B4E748FF2C2FFD45B7DF99EF1FA579F02930 \
          D3C3AA3D46F50AF699CF3E5E11E035B693542EBB5B7D756B001BA \
          792C8B6F4521A4F49DB647A37095A28482548E3C0E9DFB0C2D504 \
          BE2E9B60983660B05E45FF8847BD7392ED1010AA85589B36455B8 \
          64A682B58A87CE0BE617C838BEA0295186178B1EC2CD64044B8FF \
          4A30FFEFAE2A007E7531250E0EBBB76621CBECF255E08727BBE61 \
          178A3CF25395468F207249A97EF9A631D9CD651FD36ADC2CB00B8 \
          1663E6C89869E7C2BCB6C149E9CA97B4AC8F656F9B54A800C8104 \
          5C77A6DD75040AFB72273F1C1A2B8A0E60E60F5FA9C63AA4DBBCE \
          603BBAF99DE4EB95FED967E444FABD025D40A2D74AFE0AD427C5E \
          0D5DDFE3267DD04256752FB643D362E8DA17B5E4481A451763768 \
          04FF489DF09FDA863BD4000000067B95DE445ABF89161DFF4B91A \
          4A9E3BF156A39A4660F98F06BF3F017686D9DFC362C948646B3C9 \
          848803E6D9BA1F7D3967F709CDDD35DC77D60356F0C36808900B4 \
          91CB4ECBBABEC128E7C81A46E62A67B57640A0A78BE1CBF7DD9D4 \
          19A10CD8686D16621A80816BFDB5BDC56211D72CA70B81F1117D1 \
          29529A7570CF79CF52A7028A48538ECDD3B38D3D5D62D26246595 \
          C4FB73A525A5ED2C30524EBB1D8CC82E0C19BC4977C6898FF95FD \
          3D310B0BAE71696CEF93C6A552456BF96E9D075E383BB7543C675 \
          842BAFBFC7CDB88483B3276C29D4F0A341C2D406E40D4653B7E4D \
          045851ACF6A0A0EA9C710B805CCED4635EE8C107362F0FC8D80C1 \
          4D0AC49C516703D26D14752F34C1C0D2C4247581C18C2CF4DE48E \
          9CE949BE7C888E9CAEBE4A415E291FD107D21DC1F084B11582082 \
          49F28F4F7C7E931BA7B3BD0D824A4570"
   }
}
~~~

#Acknowledgements

Many thanks to
Scott Fluhrer,
John Mattsson,
Jim Schaad, and
Tony Putman
for their valuable review and insights.  In addition, an extra
special thank you to Jim Schaad for generating the examples in
Appendix A.
