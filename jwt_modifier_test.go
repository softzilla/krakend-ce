package krakend

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"testing"

	martian "github.com/devopsfaith/krakend-martian"
	"github.com/google/martian/parse"
)

const (
	definition = `{
	"claims.Modifier": {
		"required": true,
		"set": [
			{
				"name": "X-Auth-User",
				"type": "header",
				"claim": ["sub"]
			},
			{
				"name": "X-Auth-Groups",
				"type": "header",
				"claim": ["https://hoop.perx.ru/identity","groups"]
			},
			{
				"name": "sub",
				"type": "query",
				"claim": ["sub"]
			}
		]
	}
}`
	token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwczovL2hvb3AucGVyeC5ydS9pZGVudGl0eSI6eyJ1c2VyIjoiZ2l0aHVifDQwMzM1OCIsImdyb3VwcyI6WyJhZG1pbiIsImdyb3VwMSIsImdyb3VwMiIsInJvb3QiXX0sImlzcyI6Imh0dHBzOi8vYWR3ei5hdXRoMC5jb20vIiwic3ViIjoiZ2l0aHVifDQwMzM1OCIsImF1ZCI6IlJYOFFNQzNXWEp6WDRsSlB2SHFQWUtHTnNHS1haV2w5IiwiaWF0IjoxNTYyMDgzNTQ2LCJleHAiOjE1NjIxMTk1NDYsImF0X2hhc2giOiJQMVZQVWFqSFdoMGY1b1hTeFVZNnpBIiwibm9uY2UiOiIyMGVmOTIxMC1iMjA0LTQ2MjItODkxMi1mMjY5ODk2YTQ2ZTgifQ.b2CxR0L2ROvEC7_HPs-Ri8EQjaHOxQUHjvKq_TXC_gc"
)

func TestJWTModifier(t *testing.T) {
	r, err := parse.FromJSON([]byte(definition))
	if err != nil {
		t.Error(err)
		return
	}

	re := martian.HTTPRequestExecutor(r, func(_ context.Context, req *http.Request) (resp *http.Response, err error) {
		resp = &http.Response{
			Request:    req,
			StatusCode: 200,
		}
		return
	})

	req, _ := http.NewRequest("GET", "url", ioutil.NopCloser(bytes.NewBufferString("")))
	req.Header.Set(AuthorizationHeader, "Bearer "+token)
	resp, err := re(context.Background(), req)
	if err != nil {
		t.Error(err)
	}

	{
		if req.Header.Get("X-Auth-User") != "github|403358" {
			t.Errorf("X-Auth-User incorrect")
		}
	}

	{
		if req.Header.Get("X-Auth-Groups") != `["admin","group1","group2","root"]` {
			t.Errorf("X-Auth-Groups incorrect")
		}
	}
	{

		if req.URL.Query().Get("sub") != "github|403358" {
			t.Errorf("Query incorrect")
		}
	}

	if resp.StatusCode != 200 {
		t.Errorf("unexpected response: %v", *resp)
	}
}
