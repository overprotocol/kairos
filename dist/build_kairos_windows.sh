GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ./build/bin/geth.exe ./cmd/geth
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ./build/bin/bootnode.exe ./cmd/bootnode
zip -j dist/kairos_windows.zip build/bin/geth.exe build/bin/restoration.exe build/bin/bootnode.exe
mkdir -p dist/bin/win
cp build/bin/geth.exe dist/bin/win/kairos.exe
