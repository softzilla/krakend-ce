package krakend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/martian/parse"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

const (
	AuthorizationHeader = "Authorization"
)

func init() {
	parse.Register("claims.Modifier", modifierFromJSON)
}

// MarvelModifier contains the private and public Marvel API key
type JWTModifier struct {
	set      []Entry
	required bool
}

type Entry struct {
	Name  string   `json:"name"`
	Claim []string `json:"claim"`
	Type  string   `json:"type"`
}

type JWTModifierJSON struct {
	Set      []Entry `json:"set"`
	Required bool    `json:"required`
}

func modifierFromJSON(b []byte) (*parse.Result, error) {
	msg := &JWTModifierJSON{}
	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}
	return parse.NewResult(
		&JWTModifier{
			set:      msg.Set,
			required: msg.Required,
		},
		[]parse.ModifierType{parse.Request},
	)
}

func (m *JWTModifier) ModifyRequest(req *http.Request) error {
	claims, err := getJWTClaims(req)
	if err != nil {
		if m.required {
			return err
		}
		return nil
	}

	var queryChanged bool
	q := req.URL.Query()

	params := make([]interface{}, 0, 5)
	for _, i := range m.set {
		params = params[:0]
		for _, c := range i.Claim {
			params = append(params, c)
		}
		claim := claims.Get(params...)

		switch i.Type {
		case "header":
			req.Header.Set(i.Name, claim.ToString())
		case "query":
			q.Set(i.Name, claim.ToString())
			queryChanged = true
		}
	}

	if queryChanged {
		req.URL.RawQuery = q.Encode()
	}

	return nil
}

func getJWTClaims(req *http.Request) (a jsoniter.Any, err error) {
	defer func() {
		if err != nil {
			errors.Wrap(err, "error extract JWT Claims")
		}
	}()

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		err = fmt.Errorf("not bearer authorization")
		return
	}
	token := auth[len("Bearer "):]
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		err = fmt.Errorf("bad format of JWT token")
		return
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return jsoniter.Get(b), nil
}
