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

var testcases = []testcaseInfo{
    {"empty.basic.caatestsuite.com.", ";"},
    {"deny.basic.caatestsuite.com.", "caatestsuite.com"},
    {"*.deny.basic.caatestsuite.com.", "caatestsuite.com"},
    {"cname-deny.basic.caatestsuite.com.", "caatestsuite.com"},
    {"cname-cname-deny.basic.caatestsuite.com.", "caatestsuite.com"},
    {"sub1.cname-deny.basic.caatestsuite.com.", "caatestsuite.com"},
    {"deny.permit.basic.caatestsuite.com.", "caatestsuite.com"},
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
		caa, err := resolveCAA(testcase.subdomain, &recursions)
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
