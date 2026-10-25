package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scripted returns a readLine that serves the given answers, then EOF.
func scripted(answers ...string) func() (string, error) {
	return func() (string, error) {
		if len(answers) == 0 {
			return "", io.EOF
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
}

func testServers() []server {
	mk := func(name, cc, loc string, users int, closed bool) server {
		return server{Name: name, Country: cc, Location: loc, Users: users, UsersMax: 100, BW: int64(users * 10), BWMax: 1000, IPv4: true, closed: closed}
	}
	return []server{
		mk("Alpha", "nl", "Alblasserdam", 10, false),
		mk("Busy", "nl", "Alblasserdam", 90, false),
		mk("Dusk", "de", "Frankfurt", 40, false),
		mk("Shut", "se", "Stockholm", 0, true),
	}
}

func TestCountriesAndPick(t *testing.T) {
	all := testServers()
	cs := listCountries(all)
	if len(cs) != 3 || cs[0].Code != "de" || cs[0].Name != "Germany" || cs[1].Code != "nl" || cs[1].Open != 2 || cs[1].Servers != 2 {
		t.Fatalf("countries %+v", cs)
	}
	if cs[2].Code != "se" || cs[2].Open != 0 { // a closed-only country is listed with 0 open
		t.Fatalf("se %+v", cs[2])
	}
	if s, err := pickServer(all, "", "NL"); err != nil || s.Name != "Alpha" {
		t.Fatalf("nl best: %v %v", s, err)
	}
	if _, err := pickServer(all, "", "se"); err == nil {
		t.Fatal("closed-only country must error")
	}
	if _, err := pickServer(all, "", "zz"); err == nil || !strings.Contains(err.Error(), "countries") {
		t.Fatalf("unknown country: %v", err)
	}
	if s, err := pickServer(all, "dusk", "nl"); err != nil || s.Name != "Dusk" { // name wins
		t.Fatalf("name: %v %v", s, err)
	}
}

func TestChoose(t *testing.T) {
	opts := []option{{Label: "any"}, {Label: "Netherlands", Keys: []string{"nl", "Netherlands"}}, {Label: "Germany", Keys: []string{"de"}}}
	cases := []struct {
		in   []string
		want int
		err  error
	}{
		{[]string{""}, 0, nil},            // Enter = default
		{[]string{"3"}, 2, nil},           // number
		{[]string{"NL"}, 1, nil},          // typed code, any case
		{[]string{"netherlands"}, 1, nil}, // typed name
		{[]string{"9", "x", "2"}, 1, nil}, // invalid answers re-ask
		{[]string{"q"}, 0, errQuit},       // quit
		{[]string{"a", "b", "c", "d", "e"}, 0, errors.New("too many")},
	}
	for _, c := range cases {
		var out bytes.Buffer
		u := &ui{readLine: scripted(c.in...), out: &out}
		got, err := u.choose("Pick:", opts, 0)
		switch {
		case c.err == errQuit && !errors.Is(err, errQuit):
			t.Errorf("%v: want quit, got %v", c.in, err)
		case c.err != nil && c.err != errQuit && err == nil:
			t.Errorf("%v: want an error", c.in)
		case c.err == nil && (err != nil || got != c.want):
			t.Errorf("%v: got %d %v, want %d", c.in, got, err, c.want)
		}
	}
	if _, err := (&ui{readLine: scripted(), out: io.Discard}).choose("x", opts, 0); err == nil {
		t.Fatal("EOF must be an error, not a silent default")
	}
}

func TestInteractiveSelect(t *testing.T) {
	m := mustDoc(t, manifestXML("203.0.113.7"))
	user := &document{Keys: []node{{}, {}}}
	user.Keys[0].Attrs = attrs("name", "Default")
	user.Keys[1].Attrs = attrs("name", "Other")

	// country: Enter (best anywhere) -> server menu -> Enter -> key menu -> 2 -> listen: Enter
	var out bytes.Buffer
	u := &ui{readLine: scripted("", "", "2", ""), out: &out}
	sel, err := interactiveSelect(u, user, m)
	if err != nil {
		t.Fatal(err)
	}
	if sel.srv.Name != "Alpha" || sel.key != "Other" || sel.listen != "127.0.0.1:1080" {
		t.Fatalf("selection %+v", sel)
	}
	if strings.Contains(out.String(), "Shut") {
		t.Fatal("a closed server must not be offered")
	}

	// typed country code, second server, a bad listen address is refused then fixed
	u = &ui{readLine: scripted("nl", "3", "0.0.0.0:1080", "127.0.0.1:9050"), out: io.Discard}
	user.Keys = user.Keys[:1]
	sel, err = interactiveSelect(u, user, m)
	if err != nil {
		t.Fatal(err)
	}
	if sel.srv.Country != "nl" || sel.srv.Name != "Busy" || sel.listen != "127.0.0.1:9050" || sel.key != "" {
		t.Fatalf("selection %+v", sel)
	}
}

func TestSavedCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	t.Setenv("AIRVPN_CONFIG_DIR", dir)
	t.Setenv("AIRVPN_LOGIN", "")
	t.Setenv("AIRVPN_PASSWORD", "")
	noInput = true
	t.Cleanup(func() { noInput = false })

	if s, err := loadSaved(); s != nil || err != nil {
		t.Fatalf("nothing saved yet: %v %v", s, err)
	}
	if _, err := credentials("", ""); err == nil {
		t.Fatal("no creds and no terminal must fail, not prompt")
	}

	// default is NO: Enter, n, garbage and EOF never save
	for _, ans := range [][]string{{""}, {"n"}, {"maybe"}, {}} {
		var out bytes.Buffer
		offerSave(creds{login: "alice", password: "pw1", typed: true}, true, scripted(ans...), &out)
		if _, err := os.Stat(filepath.Join(dir, "credentials")); err == nil {
			t.Fatalf("answer %q saved", ans)
		}
		if strings.Contains(out.String(), "pw1") {
			t.Fatal("the prompt shows the password")
		}
	}
	// not asked at all: no terminal, creds not typed, creds from the saved file
	for _, c := range []struct {
		cr  creds
		can bool
	}{{creds{login: "a", password: "b", typed: true}, false}, {creds{login: "a", password: "b"}, true}, {creds{login: "a", password: "b", typed: true, fromSaved: true}, true}} {
		offerSave(c.cr, c.can, func() (string, error) { t.Fatal("must not ask"); return "", nil }, io.Discard)
	}

	// y saves, owner-only
	var out bytes.Buffer
	offerSave(creds{login: "alice", password: "pw1", typed: true}, true, scripted("Y"), &out)
	st, err := os.Stat(filepath.Join(dir, "credentials"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", st, err)
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", d.Mode().Perm())
	}
	if strings.Contains(out.String(), "pw1") {
		t.Fatal("output shows the password")
	}
	// already saved: not asked again
	offerSave(creds{login: "alice", password: "pw1", typed: true}, true, func() (string, error) { t.Fatal("asked although saved"); return "", nil }, io.Discard)
	// a changed password is a different credential: asked again
	asked := false
	offerSave(creds{login: "alice", password: "pw2", typed: true}, true, func() (string, error) { asked = true; return "n", nil }, io.Discard)
	if !asked {
		t.Fatal("changed password must be offered")
	}

	// used automatically, also without a terminal; env password and other logins bypass it
	if c, err := credentials("", ""); err != nil || c.login != "alice" || c.password != "pw1" || !c.fromSaved {
		t.Fatalf("saved use: %+v %v", c, err)
	}
	if c, err := credentials("alice", ""); err != nil || !c.fromSaved {
		t.Fatalf("same login: %+v %v", c, err)
	}
	if _, err := credentials("bob", ""); err == nil {
		t.Fatal("another login must not borrow alice's password")
	}
	t.Setenv("AIRVPN_PASSWORD", "envpw")
	if c, err := credentials("bob", ""); err != nil || c.password != "envpw" || c.fromSaved {
		t.Fatalf("env: %+v %v", c, err)
	}
	t.Setenv("AIRVPN_PASSWORD", "")

	// a file others can read is refused
	os.Chmod(filepath.Join(dir, "credentials"), 0o644)
	if _, err := loadSaved(); err == nil || !strings.Contains(err.Error(), "readable by other") {
		t.Fatalf("loose permissions accepted: %v", err)
	}
	os.Chmod(filepath.Join(dir, "credentials"), 0o600)

	// forget
	if ok, err := forgetCreds(); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if ok, _ := forgetCreds(); ok {
		t.Fatal("second forget should report nothing")
	}
	if s, _ := loadSaved(); s != nil {
		t.Fatal("still saved")
	}
}

func mustDoc(t *testing.T, x string) *document {
	t.Helper()
	var d document
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func attrs(kv ...string) []xml.Attr {
	var out []xml.Attr
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, xml.Attr{Name: xml.Name{Local: kv[i]}, Value: kv[i+1]})
	}
	return out
}
