package ingestion

import "testing"

// A scanner names some packages with their namespace: Trivy reports Log4j as
// org.apache.logging.log4j:log4j-core, where an SBOM component says log4j-core and keeps
// the group in its PURL. Reading the PURL the scanner's way is what lets the two meet.
func TestScannerNameReadsThePURLAsTrivyNamesThePackage(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1":                  "org.apache.logging.log4j:log4j-core",
		"pkg:maven/org.springframework/spring-beans@5.3.16?type=jar":            "org.springframework:spring-beans",
		"pkg:npm/%40babel/traverse@7.23.2":                                      "@babel/traverse",
		"pkg:npm/lodash@4.17.20":                                                "lodash",
		"pkg:golang/github.com/gorilla/websocket@v1.5.0":                        "github.com/gorilla/websocket",
		"pkg:composer/guzzlehttp/guzzle@7.4.0":                                  "guzzlehttp/guzzle",
		"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12":   "libssl3",
		"pkg:apk/alpine/busybox@1.36.1-r5?arch=x86_64":                          "busybox",
		"pkg:pypi/django@4.2.0":                                                 "django",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1#META-INF/x.class": "org.apache.logging.log4j:log4j-core",
		"":           "",
		"not-a-purl": "",
		"pkg:maven":  "",
	} {
		if got := ScannerName(purl); got != want {
			t.Errorf("ScannerName(%q) = %q, want %q", purl, got, want)
		}
	}
}
