package main

import (
	"fmt"
	"sort"
	"strings"
)

// countryNames covers the usual VPN locations; an unknown code is shown as is.
var countryNames = map[string]string{
	"al": "Albania", "at": "Austria", "au": "Australia", "be": "Belgium", "bg": "Bulgaria",
	"br": "Brazil", "ca": "Canada", "ch": "Switzerland", "cl": "Chile", "co": "Colombia",
	"cz": "Czechia", "de": "Germany", "dk": "Denmark", "ee": "Estonia", "es": "Spain",
	"fi": "Finland", "fr": "France", "gb": "United Kingdom", "gr": "Greece", "hk": "Hong Kong",
	"hr": "Croatia", "hu": "Hungary", "ie": "Ireland", "il": "Israel", "in": "India",
	"is": "Iceland", "it": "Italy", "jp": "Japan", "kr": "South Korea", "lt": "Lithuania",
	"lu": "Luxembourg", "lv": "Latvia", "md": "Moldova", "mx": "Mexico", "my": "Malaysia",
	"nl": "Netherlands", "no": "Norway", "nz": "New Zealand", "pl": "Poland", "pt": "Portugal",
	"ro": "Romania", "rs": "Serbia", "se": "Sweden", "sg": "Singapore", "sk": "Slovakia",
	"th": "Thailand", "tr": "Turkey", "ua": "Ukraine", "us": "United States", "za": "South Africa",
}

func countryName(code string) string {
	if n, ok := countryNames[strings.ToLower(code)]; ok {
		return n
	}
	return strings.ToUpper(code)
}

type countryInfo struct {
	Code, Name    string
	Servers, Open int
	Load          float64 // average load of the open servers
	Users         int
}

// listCountries groups the servers by country, sorted by name.
func listCountries(all []server) []countryInfo {
	by := map[string]*countryInfo{}
	for _, s := range all {
		code := strings.ToLower(s.Country)
		if code == "" {
			continue
		}
		c := by[code]
		if c == nil {
			c = &countryInfo{Code: code, Name: countryName(code)}
			by[code] = c
		}
		c.Servers++
		c.Users += s.Users
		if !s.closed && s.IPv4 {
			c.Open++
			c.Load += s.load()
		}
	}
	out := make([]countryInfo, 0, len(by))
	for _, c := range by {
		if c.Open > 0 {
			c.Load /= float64(c.Open)
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// serversIn returns the open servers of a country (all open ones if country is
// empty), least loaded first.
func serversIn(all []server, country string) []server {
	var out []server
	for _, s := range all {
		if s.closed || !s.IPv4 || (country != "" && !strings.EqualFold(s.Country, country)) {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].load() < out[j].load() })
	return out
}

// pickServer returns the named server (any country), else the least loaded open
// server, optionally limited to a country code.
func pickServer(all []server, name, country string) (server, error) {
	if name != "" {
		for _, s := range all {
			if strings.EqualFold(s.Name, name) {
				if s.closed {
					return server{}, fmt.Errorf("server %s is closed", s.Name)
				}
				return s, nil
			}
		}
		return server{}, fmt.Errorf("no server named %q (see the servers command)", name)
	}
	open := serversIn(all, country)
	if len(open) == 0 {
		if country != "" {
			return server{}, fmt.Errorf("no open server in country %q (see the countries command)", country)
		}
		return server{}, fmt.Errorf("no open server found")
	}
	return open[0], nil
}

func sortByLoad(list []server) {
	sort.SliceStable(list, func(i, j int) bool { return list[i].load() < list[j].load() })
}
