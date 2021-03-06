package options_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/influxdata/influxdb/pkg/pointer"
	_ "github.com/influxdata/influxdb/query/builtin"
	"github.com/influxdata/influxdb/task/options"
)

func scriptGenerator(opt options.Options, body string) string {
	taskData := ""
	if opt.Name != "" {
		taskData = fmt.Sprintf("%s  name: %q,\n", taskData, opt.Name)
	}
	if opt.Cron != "" {
		taskData = fmt.Sprintf("%s  cron: %q,\n", taskData, opt.Cron)
	}
	if !opt.Every.IsZero() {
		taskData = fmt.Sprintf("%s  every: %s,\n", taskData, opt.Every.String())
	}
	if opt.Offset != nil && !(*opt.Offset).IsZero() {
		taskData = fmt.Sprintf("%s  offset: %s,\n", taskData, opt.Offset.String())
	}
	if opt.Concurrency != nil && *opt.Concurrency != 0 {
		taskData = fmt.Sprintf("%s  concurrency: %d,\n", taskData, *opt.Concurrency)
	}
	if opt.Retry != nil && *opt.Retry != 0 {
		taskData = fmt.Sprintf("%s  retry: %d,\n", taskData, *opt.Retry)
	}
	if body == "" {
		body = `from(bucket: "test")
    |> range(start:-1h)`
	}

	return fmt.Sprintf(`option task = {
%s
}

%s`, taskData, body)
}

func TestNegDurations(t *testing.T) {
	dur := options.MustParseDuration("-1m")
	d, err := dur.DurationFrom(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d != -time.Minute {
		t.Fatalf("expected duration to be -1m but was %s", d)
	}
}

func TestFromScript(t *testing.T) {
	for _, c := range []struct {
		script    string
		exp       options.Options
		shouldErr bool
	}{
		{script: scriptGenerator(options.Options{Name: "name0", Cron: "* * * * *", Concurrency: pointer.Int64(2), Retry: pointer.Int64(3), Offset: options.MustParseDuration("-1m")}, ""),
			exp: options.Options{Name: "name0",
				Cron:        "* * * * *",
				Concurrency: pointer.Int64(2),
				Retry:       pointer.Int64(3),
				Offset:      options.MustParseDuration("-1m")}},
		{script: scriptGenerator(options.Options{Name: "name1", Every: *(options.MustParseDuration("5s"))}, ""), exp: options.Options{Name: "name1", Every: *(options.MustParseDuration("5s")), Concurrency: pointer.Int64(1), Retry: pointer.Int64(1)}},
		{script: scriptGenerator(options.Options{Name: "name2", Cron: "* * * * *"}, ""), exp: options.Options{Name: "name2", Cron: "* * * * *", Concurrency: pointer.Int64(1), Retry: pointer.Int64(1)}},
		{script: scriptGenerator(options.Options{Name: "name3", Every: *(options.MustParseDuration("1h")), Cron: "* * * * *"}, ""), shouldErr: true},
		{script: scriptGenerator(options.Options{Name: "name4", Concurrency: pointer.Int64(1000), Every: *(options.MustParseDuration("1h"))}, ""), shouldErr: true},
		{script: "option task = {\n  name: \"name5\",\n  concurrency: 0,\n  every: 1m0s,\n\n}\n\nfrom(bucket: \"test\")\n    |> range(start:-1h)", shouldErr: true},
		{script: "option task = {\n  name: \"name6\",\n  concurrency: 1,\n  every: 1,\n\n}\n\nfrom(bucket: \"test\")\n    |> range(start:-1h)", shouldErr: true},
		{script: scriptGenerator(options.Options{Name: "name7", Retry: pointer.Int64(20), Every: *(options.MustParseDuration("1h"))}, ""), shouldErr: true},
		{script: "option task = {\n  name: \"name8\",\n  retry: 0,\n  every: 1m0s,\n\n}\n\nfrom(bucket: \"test\")\n    |> range(start:-1h)", shouldErr: true},
		{script: scriptGenerator(options.Options{Name: "name9"}, ""), shouldErr: true},
		{script: scriptGenerator(options.Options{}, ""), shouldErr: true},
	} {
		o, err := options.FromScript(c.script)
		if c.shouldErr && err == nil {
			t.Fatalf("script %q should have errored but didn't", c.script)
		} else if !c.shouldErr && err != nil {
			t.Fatalf("script %q should not have errored, but got %v", c.script, err)
		}

		if err != nil {
			continue
		}
		if !cmp.Equal(o, c.exp) {
			t.Fatalf("script %q got unexpected result -got/+exp\n%s", c.script, cmp.Diff(o, c.exp))
		}
	}
}

func BenchmarkFromScriptFunc(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := options.FromScript(`option task = {every: 20s, name: "foo"} from(bucket:"x") |> range(start:-1h)`)
		if err != nil {
			fmt.Printf("error: %v", err)
		}
	}
}

func TestFromScriptWithUnknownOptions(t *testing.T) {
	const optPrefix = `option task = { name: "x", every: 1m`
	const bodySuffix = `} from(bucket:"b") |> range(start:-1m)`

	// Script without unknown option should be good.
	if _, err := options.FromScript(optPrefix + bodySuffix); err != nil {
		t.Fatal(err)
	}

	_, err := options.FromScript(optPrefix + `, Offset: 2s, foo: "bar"` + bodySuffix)
	if err == nil {
		t.Fatal("expected error from unknown option but got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Offset") || !strings.Contains(msg, "foo") {
		t.Errorf("expected error to mention unrecognized options, but it said: %v", err)
	}

	validOpts := []string{"name", "cron", "every", "offset", "concurrency", "retry"}
	for _, o := range validOpts {
		if !strings.Contains(msg, o) {
			t.Errorf("expected error to mention valid option %q but it said: %v", o, err)
		}
	}
}

func TestValidate(t *testing.T) {
	good := options.Options{Name: "x", Cron: "* * * * *", Concurrency: pointer.Int64(1), Retry: pointer.Int64(1)}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}

	bad := new(options.Options)
	*bad = good
	bad.Name = ""
	if err := bad.Validate(); err == nil {
		t.Error("expected error for options without name")
	}

	*bad = good
	bad.Cron = ""
	if err := bad.Validate(); err == nil {
		t.Error("expected error for options without cron or every")
	}

	*bad = good
	bad.Every = *options.MustParseDuration("1m")
	if err := bad.Validate(); err == nil {
		t.Error("expected error for options with both cron and every")
	}

	*bad = good
	bad.Cron = "not a cron string"
	if err := bad.Validate(); err == nil {
		t.Error("expected error for options with invalid cron")
	}

	*bad = good
	bad.Cron = ""
	bad.Every = *options.MustParseDuration("-1m")
	if err := bad.Validate(); err == nil {
		t.Error("expected error for negative every")
	}

	*bad = good
	bad.Offset = options.MustParseDuration("1500ms")
	if err := bad.Validate(); err == nil {
		t.Error("expected error for sub-second delay resolution")
	}

	*bad = good
	bad.Concurrency = pointer.Int64(0)
	if err := bad.Validate(); err == nil {
		t.Error("expected error for 0 concurrency")
	}

	*bad = good
	bad.Concurrency = pointer.Int64(math.MaxInt64)
	if err := bad.Validate(); err == nil {
		t.Error("expected error for concurrency too large")
	}

	*bad = good
	bad.Retry = pointer.Int64(0)
	if err := bad.Validate(); err == nil {
		t.Error("expected error for 0 retry")
	}

	*bad = good
	bad.Retry = pointer.Int64(math.MaxInt64)
	if err := bad.Validate(); err == nil {
		t.Error("expected error for retry too large")
	}
}

func TestEffectiveCronString(t *testing.T) {
	for _, c := range []struct {
		c   string
		e   options.Duration
		exp string
	}{
		{c: "10 * * * *", exp: "10 * * * *"},
		{e: *(options.MustParseDuration("10s")), exp: "@every 10s"},
		{exp: ""},
	} {
		o := options.Options{Cron: c.c, Every: c.e}
		got := o.EffectiveCronString()
		if got != c.exp {
			t.Fatalf("exp cron string %q, got %q for %v", c.exp, got, o)
		}
	}
}

func TestDurationMarshaling(t *testing.T) {
	t.Run("unmarshaling", func(t *testing.T) {
		now := time.Now()
		dur1 := options.Duration{}
		if err := dur1.UnmarshalText([]byte("1h10m3s")); err != nil {
			t.Fatal(err)
		}
		d1, err1 := dur1.DurationFrom(now)
		if err1 != nil {
			t.Fatal(err1)
		}

		dur2 := options.Duration{}
		if err := dur2.Parse("1h10m3s"); err != nil {
			t.Fatal(err)
		}
		d2, err2 := dur2.DurationFrom(now)
		if err2 != nil {
			t.Fatal(err2)
		}

		if d1 != d2 || d1 != time.Hour+10*time.Minute+3*time.Second {
			t.Fatal("Parse and Marshaling do not give us the same result")
		}
	})

	t.Run("marshaling", func(t *testing.T) {
		dur := options.Duration{}
		if err := dur.UnmarshalText([]byte("1h10m3s")); err != nil {
			t.Fatal(err)
		}
		if dur.String() != "1h10m3s" {
			t.Fatalf("duration string should be \"1h10m3s\" but was %s", dur.String())
		}
		text, err := dur.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if string(text) != "1h10m3s" {
			t.Fatalf("duration text should be \"1h10m3s\" but was %s", text)
		}
	})

	t.Run("parse zero", func(t *testing.T) {
		dur := options.Duration{}
		if err := dur.UnmarshalText([]byte("0h0s")); err != nil {
			t.Fatal(err)
		}
		if !dur.IsZero() {
			t.Fatalf("expected duration \"0s\" to be zero but was %s", dur.String())
		}
	})
}

func TestDurationMath(t *testing.T) {
	dur := options.MustParseDuration("10s")
	d, err := dur.DurationFrom(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if d != 10*time.Second {
		t.Fatalf("expected duration to be 10s but it was %s", d)
	}
}
