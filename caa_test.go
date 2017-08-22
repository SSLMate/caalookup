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
	"fmt"
	"github.com/miekg/dns"
	"testing"
)

type testcaseInfo struct {
	subdomain string
	issue     string
}

const TEST_DOMAIN = "test.caarecord.org."

var testcases = []testcaseInfo{
	{"none", ""},
	{"caa1", "1.example.com"},
	{"child.caa1", "1.example.com"},
	{"grand.child.caa1", "1.example.com"},
	{"cname-to-none", ""},
	{"cname-to-caa1", "1.example.com"},
	{"child.cname-to-caa1", "1.example.com"},
	{"grand.child.cname-to-caa1", "1.example.com"},
	{"cname-to-caa1-child", "1.example.com"},
	{"child.cname-to-caa1-child", "1.example.com"},
	{"grand.child.cname-to-caa1-child", "1.example.com"},
	{"dname-to-none", ""},
	{"dname-to-caa1", "1.example.com"},
	{"dname-to-caa1-child", "1.example.com"},
	{"child.dname-to-none", ""},
	{"child.dname-to-caa1", "1.example.com"},
	{"child.dname-to-caa1-child", "1.example.com"},
	{"caa3.dname-to-caa1", "3.example.com"},
	{"child.caa3.dname-to-caa1", "3.example.com"},
	{"caa4-and-dname", "4.example.com"},
	{"caa2", "2.example.com"},
	{"cname-to-none.caa2", "2.example.com"},
	{"cname-to-caa1.caa2", "1.example.com"},
	{"cname-to-caa1-child.caa2", "1.example.com"},
	{"dname-to-none.caa2", "2.example.com"},
	{"dname-to-caa1.caa2", "1.example.com"},
	{"dname-to-caa1-child.caa2", "1.example.com"},
	{"child.dname-to-none.caa2", "2.example.com"},
	{"child.dname-to-caa1.caa2", "1.example.com"},
	{"child.dname-to-caa1-child.caa2", "1.example.com"},
	{"caa3.dname-to-caa1.caa2", "3.example.com"},
}

func extractIssue(caa []*dns.CAA) (string, error) {
	if len(caa) == 0 {
		return "", nil
	}
	if len(caa) > 1 {
		return "", fmt.Errorf("Expected no more than one CAA record, got %d", len(caa))
	}
	if caa[0].Tag != "issue" {
		return "", fmt.Errorf("Expected an issue record, got '%s' instead", caa[0].Tag)
	}
	return caa[0].Value, nil
}

func TestResolveCAA(t *testing.T) {
	for _, testcase := range testcases {
		recursions := 0
		caa, err := resolveCAA(testcase.subdomain+"."+TEST_DOMAIN, &recursions)
		if err != nil {
			t.Errorf("%s: got error: %s", testcase.subdomain, err)
			continue
		}
		issue, err := extractIssue(caa)
		if err != nil {
			t.Errorf("%s: %s", testcase.subdomain, err)
			continue
		}
		if issue != testcase.issue {
			t.Errorf("%s: Expected issue '%s', got '%s'", testcase.subdomain, testcase.issue, issue)
			continue
		}
	}
}
