GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./build/bin/geth ./cmd/geth
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o ./build/bin/bootnode ./cmd/bootnode
zip -j dist/kairos_darwin_amd64.zip build/bin/geth build/bin/restoration build/bin/bootnode
mkdir -p dist/bin/mac/amd64
cp build/bin/geth dist/bin/mac/amd64/kairos
