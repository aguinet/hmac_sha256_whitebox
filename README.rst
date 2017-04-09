C++14 HMAC-SHA256 Whitebox
==========================

WARNING
-------

This whitebox might be easily breakable. This is really for education purpose
only and an exercise to play with C++14.

Introduction
------------

This is an example of how to use the C++11/14 constexpr facilities and compiler
optimizations to create an HMAC whitebox.

For the record, an HMAC for a secret ``S`` and a hash algorithm ``H`` is
roughly computed like this:

.. code::

  HMAC = H(S^0x5C || H(S^0x36 || message))

where ``||`` is the concatenation operator. ``S`` might be transformed so that it
is the size of the block of the underlying hash algorithm. See
https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Implementation
for a detail explanation.

As a reminder, most of hash algorithms (and this is the case for SHA256)
generally process data-blocks, using padding for the remaining bytes (this is
similar to what block-cipher do).

Principle
---------

The principle of this whitebox is really simple: we precompute the state of the
hash after the processing of ``S ^ 0x36`` and ``S ^ 0x5C``. We thus ends-up
with two pre-computed states, that we then use as a "starting" point for the
SHA256 hash.

How does this work?
-------------------

In order to do this, you can manually precompute this state using an external
program, then inject them into your final code. The idea here is not to do that
and let the compiler do it for you. This has the advantage of having the
whitebox "self-construct", and not rely on any external tools.

We mainly rely on these things: the C++11/14 constexpr operator, clang
loop-unrolling pragma
(https://clang.llvm.org/docs/AttributeReference.html#pragma-unroll-pragma-nounroll)
and clang optimizations.

Indeed, the constexpr keyword allow the definition of "constexpr" functions,
which can be used in constexpr expressions. These expressions will be evaluated
at compile-time. We use them to compute ``S ^ 0x36`` and ``S ^ 0x5C``.

Then, we rely on loop unrolling and general compiler optimizations to
precompute the state. Indeed, using clang's unroll pragma, we unroll the
various rounds of the SHA256 block function. Then, we inline this function.
Unrolling allows optimizations to precompute the state in the end [1].

Doing so has the advantage of having only one SHA256 block function in our
code, but has two big drawbacks: it relies on compiler optimizations, whose
transformations are not guaranted by the C++ standard (that is we might end-up
with a code where the folding didn't happen, and thus the hmac key ends-up in
the code), and produces a non-negligeable quantity of code in the end (stripped
binary is ~53KB in the end, versus ~11KB for the non unrolled version).

Improvements
------------

Here is a list of possible improvements:

* make a constexpr version of the ``transform`` function. This will ensure by the
  C++ standard that the states are precompiled.
* with this, make a non-unrolled version of ``transform``, to minimize code size

These improvements has the drawback of having two definitions of the
``transform`` function to maintain.

On a more general note:

* make a test that checks that the original SHA256 state constants are not in the final code
* make real unit-tests for compliance checking

Usage
-----

You need to compile this code with clang. This has only been tested using clang 4.0:

.. code:: bash

  $ clang++-4.0 sha256_wb.cpp -O2 -o sha256_wb -std=c++14

You can compare the output with the Python reference script in this repo:

.. code:: bash

  $ ./sha256_wb coucou
  5b7ba9d257738744264ae49133409b50714f0ac06875a2befa15687409549f3d
  $ python ./sha256_hmac.py coucou
  5b7ba9d257738744264ae49133409b50714f0ac06875a2befa15687409549f3d

You can also use IDA to verify that the original SHA256 state isn't present in
the final binary code.

[1]: we can note that clang needs the unrolling to happen so that
constant folding is working. It could be enhanced to understand for-loop with
compile-time indices.
