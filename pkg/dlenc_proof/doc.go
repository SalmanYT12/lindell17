/*
Package dlencproof implements the interactive proof which proves that
x1 = Dec_sk(c) and Q1 = x1 * G as described in section "Protocol 6.1" of the
paper https://eprint.iacr.org/2017/552.pdf.

Note that this proof DOES NOT run the range proof as a subprotocol.
*/
package dlencproof
