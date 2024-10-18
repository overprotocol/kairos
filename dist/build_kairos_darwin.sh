GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./build/bin/geth ./cmd/geth
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o ./build/bin/bootnode ./cmd/bootnode
zip -j dist/kairos_darwin.zip build/bin/restoration build/bin/geth build/bin/bootnode
mkdir -p dist/bin/mac/arm64
cp build/bin/geth dist/bin/mac/arm64/kairos
