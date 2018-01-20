# rc4c-go

RC4C cipher, it's RC4 extension with two S-boxes on key and IV, and with 3 scrambling phases.

## Installation

With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:
```sh
go get github.com/schwarzlichtbezirk/rc4c-go
```

## Usage

Package RC4C has same implementation as standard RC4. Sample usage for encrypt / decrypt message:
```go
func encryptmsg(key, iv []byte, enc, text []byte) {
	var c, _ = rc4c.NewCipher(key, iv)
	c.XORKeyStream(enc, text)
}

func decryptmsg(key, iv []byte, enc, text []byte) {
	var c, _ = rc4c.NewCipher(key, iv)
	c.XORKeyStream(enc, text)
}
```

## License

Author: &copy; schwarzlichtbezirk (schwarzlichtbezirk@gmail.com)  
The project is released under the [MIT license](http://www.opensource.org/licenses/MIT).
