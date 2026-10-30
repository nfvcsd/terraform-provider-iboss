package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// FlexInt decodes an integer that the API may encode as a JSON number, a
// numeric string, or a boolean (documented examples use 0/1 integers for
// flags, while the collection's scripts compare some values with strings).
type FlexInt struct {
	Int64 int64
	Valid bool
}

func (f *FlexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case bytes.Equal(b, []byte("null")):
		*f = FlexInt{}
		return nil
	case bytes.Equal(b, []byte("true")):
		*f = FlexInt{Int64: 1, Valid: true}
		return nil
	case bytes.Equal(b, []byte("false")):
		*f = FlexInt{Int64: 0, Valid: true}
		return nil
	}
	s := string(b)
	if strings.HasPrefix(s, `"`) {
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			*f = FlexInt{}
			return nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("expected an integer, got %s", string(b))
	}
	*f = FlexInt{Int64: n, Valid: true}
	return nil
}

func (f FlexInt) MarshalJSON() ([]byte, error) {
	if !f.Valid {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatInt(f.Int64, 10)), nil
}

// Bool reports a 0/1 flag as a boolean (any non-zero value is true).
func (f FlexInt) Bool() bool { return f.Valid && f.Int64 != 0 }

// Int returns a valid FlexInt.
func Int(n int64) FlexInt { return FlexInt{Int64: n, Valid: true} }

// BoolInt encodes a boolean as the API's 0/1 integer flag.
func BoolInt(b bool) FlexInt {
	if b {
		return Int(1)
	}
	return Int(0)
}

func decode(b []byte, out any) error {
	return json.Unmarshal(b, out)
}
