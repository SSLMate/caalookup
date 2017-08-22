// Copyright (c) 2017 Opsmate, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

func queryDNS(domain string, rrtype uint16) (*dns.Msg, error) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{domain, rrtype, dns.ClassINET},
		},
	}
	udpClient := &dns.Client{}
	tcpClient := &dns.Client{Net: "tcp"}

	resp, _, err := udpClient.Exchange(msg, "127.0.0.1:53")
	if err == dns.ErrTruncated || (err == nil && resp.Truncated) {
		resp, _, err = tcpClient.Exchange(msg, "127.0.0.1:53")
	}
	if err != nil {
		return nil, err
	}
	if !(resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
		return nil, errors.New("Received " + dns.RcodeToString[resp.Rcode] + " when looking up " + dns.TypeToString[rrtype] + " for " + domain)
	}
	return resp, nil
}

func queryDNAME(domain string) (string, error) {
	resp, err := queryDNS(domain, dns.TypeDNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if dname, isDNAME := rr.(*dns.DNAME); isDNAME {
			return dname.Target, nil
		}
	}
	return "", nil
}

func queryCNAME(domain string) (string, error) {
	resp, err := queryDNS(domain, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range resp.Answer {
		if cname, isCNAME := rr.(*dns.CNAME); isCNAME {
			return cname.Target, nil
		}
	}
	return "", nil
}

func queryCAA(domain string) ([]*dns.CAA, error) {
	caas := []*dns.CAA{}
	resp, err := queryDNS(domain, dns.TypeCAA)
	if err != nil {
		return nil, err
	}
	for _, rr := range resp.Answer {
		if caa, isCAA := rr.(*dns.CAA); isCAA {
			caas = append(caas, caa)
		}
	}
	return caas, nil
}

func parent(domain string) string {
	dot := strings.IndexByte(domain, '.')
	if dot == -1 {
		panic("Not a valid domain name")
	}
	parent := domain[dot+1:]
	if parent == "" {
		return "."
	} else {
		return parent
	}
}

func resolveCAA(domain string, recursions *int) ([]*dns.CAA, error) {
	if *recursions >= 100 {
		return nil, errors.New("Too many recursions")
	}
	(*recursions)++

	if domain == "." {
		return []*dns.CAA{}, nil
	}
	cnameTarget, err := queryCNAME(domain)
	if err != nil {
		return nil, err
	}
	if cnameTarget != "" {
		// This implies domain has no CAA or DNAME records, since CNAME can't coexist with other record types
		caa, err := resolveCAA(cnameTarget, recursions)
		if err != nil {
			return nil, err
		}
		if len(caa) != 0 {
			return caa, nil
		}
	} else {
		caa, err := queryCAA(domain)
		if err != nil {
			return nil, err
		}
		if len(caa) != 0 {
			return caa, nil
		}
		dnameTarget, err := queryDNAME(domain)
		if err != nil {
			return nil, err
		}
		if dnameTarget != "" {
			caa, err := resolveCAA(dnameTarget, recursions)
			if err != nil {
				return nil, err
			}
			if len(caa) != 0 {
				return caa, nil
			}
		}
	}
	return resolveCAA(parent(domain), recursions)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: caalookup domain\n")
		os.Exit(2)
	}
	domain := os.Args[1]
	if len(domain) == 0 || domain[len(domain)-1] != '.' {
		fmt.Fprintf(os.Stderr, "Error: %s: is not a fully qualified domain name\n", domain)
		os.Exit(2)
	}

	recursions := 0
	caa, err := resolveCAA(domain, &recursions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: %s\n", domain, err)
		os.Exit(1)
	}
	for _, rec := range caa {
		fmt.Println(rec.String())
	}
}
