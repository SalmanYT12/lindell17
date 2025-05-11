# Lindell17

Implementation of the paper [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552.pdf) by Yehuda Lindell.

In addition to the standard [Two-Party ECDSA](https://muens.io/two-party-ecdsa/) implementation it also comes with an [Adaptor Signature](https://muens.io/adaptor-signature/) variant that follows the paper [Anonymous Multi-Hop Locks for Blockchain Scalability and Interoperability](https://eprint.iacr.org/2018/472.pdf) by Malavolta et al.

Generated ECDSA signatures carry a recovery bit which can be used to recover the public key from the signature.

An interactive proof allows one to prove that a value encrypted using the [Paillier Cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) is the encryption of a discrete logarithm.

## Setup

1. `git clone <url>`
2. `asdf install` (optional)
3. `go test -count 1 -race ./...`

## Useful Commands

```sh
go run <package-path>
go build [<package-path>]

go test [<package-path>][/...] [-v] [-cover] [-race] [-short] [-parallel <number>]
go test -bench=. [<package-path>] [-count <number>] [-benchmem] [-benchtime 2s] [-memprofile <name>]

go test -coverprofile <name> [<package-path>]
go tool cover -html <name>
go tool cover -func <name>

go fmt [<package-path>]

go mod init [<module-path>]
go mod tidy
```

## Useful Resources

- [Go - Learn](https://go.dev/learn)
- [Go - Documentation](https://go.dev/doc)
- [Go - A Tour of Go](https://go.dev/tour)
- [Go - Effective Go](https://go.dev/doc/effective_go)
- [Go - Playground](https://go.dev/play)
- [Go by Example](https://gobyexample.com)
- [100 Go Mistakes and How to Avoid Them](https://100go.co)
