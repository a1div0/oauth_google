package oauth_google

import (
    "testing"
)

func TestServiceName(t *testing.T) {
    s := OAuthGoogle {}
    name := s.ServiceName()
    if (name != "google") {
        t.Error("ServiceName = '", name, "'\nа должно быть = 'google'")
    }
}
