package app

// AirVPN's public RSA key (4096 bit, exponent 65537) that wraps the one-time
// AES session key of every API request, and the bootstrap endpoints. Both are
// public data copied from the provider definition shipped with Eddie
// (resources/providers/AirVPN.json). Plain HTTP is by design: the payload is
// encrypted.
const (
	airvpnRSAModulus  = "wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc="
	airvpnRSAExponent = "AQAB"
)

var airvpnBootstrap = []string{
	"http://63.33.78.166",
	"http://54.93.175.114",
	"http://82.196.3.205",
	"http://63.33.116.50",
	"http://[2a03:b0c0:0:1010::9b:c001]",
	"http://bootme.org",
}
