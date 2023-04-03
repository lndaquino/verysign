package verysign

const (
	keyIdTokenHeaderKey = "kid"
)

type Vendor int

const (
	GCP Vendor = iota
)

var urls map[Vendor]string = map[Vendor]string{
	GCP: "https://www.googleapis.com/oauth2/v1/certs",
}
