# OPE Go bindings

cgo wrapper over `libope_ffi`.

```bash
cargo build -p ope-ffi --release
cd bindings/go/ope && CGO_ENABLED=1 go test -v .
```

Import: `github.com/ClawBay/OPE/bindings/go/ope`
