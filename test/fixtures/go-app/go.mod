module example.com/go-app

go 1.21

require (
	github.com/gin-gonic/gin v1.6.0
	gopkg.in/yaml.v2 v2.2.2
)

require (
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
	golang.org/x/text v0.3.2 // indirect
)

replace github.com/old/thing v1.0.0 => github.com/new/thing v1.2.0
