package labrecord

import (
	"strings"
	"testing"
	"testing/fstest"
)

const good = `{"lab":"public-access-lab-aws","title":"S3 Block Public Access","command":"make public-access-lab-aws",
  "region":"eu-north-1","engine":"v1.31.0-3-g76882f9","ran_at":"2026-10-05T10:00:00Z","cost":"free","checks":[
  {"case":"bucketblock","question":"Does a stranger get in?","referee":"an anonymous request","aws":"403 AccessDenied","engine":"closed","verdict":"agree"},
  {"case":"accountblock","question":"Does a stranger get in?","referee":"an anonymous request","aws":"403 AccessDenied","engine":"open","verdict":"disagree"}]}`

// The records built into this binary are the ones an instance shows: they must load.
func TestTheBuiltInRecordsLoad(t *testing.T) {
	runs, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if r.Count(Agree)+r.Count(Disagree)+r.Count(Unsettled) != len(r.Checks) {
			t.Errorf("%s: a check without a verdict", r.Lab)
		}
	}
}

func TestARecordLoadsNewestFirst(t *testing.T) {
	older := strings.Replace(strings.Replace(good, "2026-10-05", "2026-10-02", 1), "public-access-lab-aws", "entrypoints-lab-aws", 2)
	runs, err := load(fstest.MapFS{
		"records/old.json":  {Data: []byte(older)},
		"records/new.json":  {Data: []byte(good)},
		"records/README.md": {Data: []byte("not a record")},
	}, "records")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Lab != "public-access-lab-aws" {
		t.Fatalf("want the newest run first, got %+v", runs)
	}
	if runs[0].Count(Agree) != 1 || runs[0].Count(Disagree) != 1 {
		t.Errorf("counts: agree %d, disagree %d", runs[0].Count(Agree), runs[0].Count(Disagree))
	}
}

// Records are published with every build, so one that would publish an AWS account ID, or
// that does not say what it checked, must not load at all.
func TestABadRecordIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"an account ID":       strings.Replace(good, `"bucketblock"`, `"arn:aws:iam::123456789012:role/x"`, 1),
		"an unknown field":    strings.Replace(good, `"cost":"free"`, `"cost":"free","account":"x"`, 1),
		"a verdict of no set": strings.Replace(good, `"verdict":"agree"`, `"verdict":"probably"`, 1),
		"no checks":           good[:strings.Index(good, `"checks"`)] + `"checks":[]}`,
		"no date":             strings.Replace(good, `"ran_at":"2026-10-05T10:00:00Z",`, "", 1),
		"no referee":          strings.Replace(good, `"referee":"an anonymous request"`, `"referee":""`, 1),
	} {
		if _, err := load(fstest.MapFS{"records/r.json": {Data: []byte(body)}}, "records"); err == nil {
			t.Errorf("%s: the record loaded", name)
		}
	}
}
