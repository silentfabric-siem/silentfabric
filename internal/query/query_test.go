package query

import (
	"reflect"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	q, err := Parse(`failed "bad password" host:web01 -event.outcome:success user.name:adm* "a:b" -`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Term{
		{Value: "failed"},
		{Value: "bad password"},
		{Field: "host", Value: "web01"},
		{Field: "event.outcome", Value: "success", Negate: true},
		{Field: "user.name", Value: "adm*"},
		{Value: "a:b"},
		{Value: "-"},
	}
	if !reflect.DeepEqual(q.Terms, want) {
		t.Fatalf("got %+v", q.Terms)
	}
}

func TestParseUnclosedQuote(t *testing.T) {
	if _, err := Parse(`"oops`); err == nil {
		t.Fatal("want error")
	}
}

func TestWhereIsParameterized(t *testing.T) {
	q, _ := Parse(`'; DROP TABLE events; -- host:x -user.name:a_b*`)
	from, to := time.Unix(0, 0), time.Unix(10, 0)
	q.From, q.To = from, to
	where, args := q.Where()

	wantSQL := "time >= ? AND time < ? AND positionCaseInsensitive(raw, ?) > 0 AND positionCaseInsensitive(raw, ?) > 0 AND positionCaseInsensitive(raw, ?) > 0 AND positionCaseInsensitive(raw, ?) > 0 AND NOT (positionCaseInsensitive(raw, ?) > 0) AND host = ? AND NOT (fields[?] ILIKE ?)"
	if where != wantSQL {
		t.Fatalf("where = %s", where)
	}
	if args[len(args)-1] != `a\_b%` || args[len(args)-2] != "user.name" || args[len(args)-3] != "x" {
		t.Fatalf("args = %v", args)
	}
}

func TestParseRange(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	from, _, err := ParseRange("7d", now)
	if err != nil || !from.Equal(now.AddDate(0, 0, -7)) {
		t.Fatalf("from %v err %v", from, err)
	}
	for _, bad := range []string{"7", "0h", "5y", "xh"} {
		if _, _, err := ParseRange(bad, now); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}
