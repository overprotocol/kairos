GOOS=linux GOARCH=amd64 go build -ldflags "-s -extldflags '-Wl,-z,stack-size=0x800000'" -trimpath -o ./build/bin/geth ./cmd/geth
GOOS=linux GOARCH=amd64 go build -ldflags "-s -extldflags '-Wl,-z,stack-size=0x800000'" -trimpath -o ./build/bin/bootnode ./cmd/bootnode
zip -j dist/kairos_linux.zip build/bin/geth build/bin/restoration build/bin/bootnode
mkdir -p dist/bin/linux
cp build/bin/geth dist/bin/linux/kairos