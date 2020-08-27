
-- Prerequisites --

counterfeiter is installed, if not:
GO111MODULE=off go get -u github.com/maxbrunsfeld/counterfeiter

then:
- export PATH=$PATH:$GOPATH/bin
- go generate ./... 
- go test
