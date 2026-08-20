package diff

import (
	"strings"
	"testing"
)

const simplePatch = `diff --git a/api/handler.go b/api/handler.go
index 1234567..89abcde 100644
--- a/api/handler.go
+++ b/api/handler.go
@@ -10,7 +10,8 @@ func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
 	user := r.FormValue("user")
 	pass := r.FormValue("pass")
-	if !auth.Verify(user, pass) {
+	if user == "admin" {
+		// bypass
 		return
 	}
 	s.issueSession(w, user)
`

func TestParseSimple(t *testing.T) {
	d, err := ParseString(simplePatch)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(d.Files) != 1 {
		t.Fatalf("want 1 file, got %d", len(d.Files))
	}
	f := d.Files[0]
	if f.Path != "api/handler.go" {
		t.Errorf("path = %q", f.Path)
	}
	if f.Status != Modified {
		t.Errorf("status = %v", f.Status)
	}
	if f.Additions != 2 || f.Deletions != 1 {
		t.Errorf("additions/deletions = %d/%d, want 2/1", f.Additions, f.Deletions)
	}
	if len(f.Hunks) != 1 {
		t.Fatalf("want 1 hunk, got %d", len(f.Hunks))
	}
	h := f.Hunks[0]
	if h.Section != "func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {" {
		t.Errorf("section = %q", h.Section)
	}
	if h.OldStart != 10 || h.OldCount != 7 || h.NewStart != 10 || h.NewCount != 8 {
		t.Errorf("hunk range = -%d,%d +%d,%d", h.OldStart, h.OldCount, h.NewStart, h.NewCount)
	}
}

func TestLineNumbering(t *testing.T) {
	d, err := ParseString(simplePatch)
	if err != nil {
		t.Fatal(err)
	}
	var removed, added []Line
	d.Files[0].Lines(func(_ *Hunk, l Line) bool {
		switch l.Kind {
		case Removed:
			removed = append(removed, l)
		case Added:
			added = append(added, l)
		}
		return true
	})
	if len(removed) != 1 || removed[0].OldLine != 12 || removed[0].NewLine != 0 {
		t.Errorf("removed = %+v, want old line 12 and no new line", removed)
	}
	if len(added) != 2 || added[0].NewLine != 12 || added[1].NewLine != 13 {
		t.Errorf("added = %+v, want new lines 12 and 13", added)
	}
	// Context lines carry both numbers, which is what lets a rule anchor to a
	// surviving line.
	var firstContext Line
	d.Files[0].Lines(func(_ *Hunk, l Line) bool {
		if l.Kind == Context {
			firstContext = l
			return false
		}
		return true
	})
	if firstContext.OldLine != 10 || firstContext.NewLine != 10 {
		t.Errorf("first context = %+v", firstContext)
	}
}

func TestParseCreateDeleteRename(t *testing.T) {
	patch := `diff --git a/new.py b/new.py
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+import os
+os.system("echo hi")
diff --git a/gone.py b/gone.py
deleted file mode 100644
index e69de29..0000000
--- a/gone.py
+++ /dev/null
@@ -1,1 +0,0 @@
-print("bye")
diff --git a/old/name.py b/new/name.py
similarity index 92%
rename from old/name.py
rename to new/name.py
index 1111111..2222222 100644
--- a/old/name.py
+++ b/new/name.py
@@ -1,1 +1,1 @@
-x = 1
+x = 2
`
	d, err := ParseString(patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 3 {
		t.Fatalf("want 3 files, got %d", len(d.Files))
	}
	if d.Files[0].Status != Created || d.Files[0].Path != "new.py" {
		t.Errorf("file 0 = %+v", d.Files[0])
	}
	if d.Files[1].Status != Deleted || d.Files[1].Path != "gone.py" {
		t.Errorf("file 1 = %+v", d.Files[1])
	}
	if d.Files[2].Status != Renamed ||
		d.Files[2].Path != "new/name.py" || d.Files[2].OldPath != "old/name.py" {
		t.Errorf("file 2 = %+v", d.Files[2])
	}
}

func TestParseBinary(t *testing.T) {
	patch := `diff --git a/logo.png b/logo.png
index 1111111..2222222 100644
Binary files a/logo.png and b/logo.png differ
`
	d, err := ParseString(patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 1 || !d.Files[0].Binary {
		t.Fatalf("want one binary file, got %+v", d.Files)
	}
}

func TestParseQuotedPath(t *testing.T) {
	patch := "diff --git \"a/src/my file.go\" \"b/src/my file.go\"\n" +
		"--- \"a/src/my file.go\"\n" +
		"+++ \"b/src/my file.go\"\n" +
		"@@ -1 +1 @@\n" +
		"-a\n+b\n"
	d, err := ParseString(patch)
	if err != nil {
		t.Fatal(err)
	}
	if d.Files[0].Path != "src/my file.go" {
		t.Errorf("path = %q", d.Files[0].Path)
	}
}

func TestParseHunkHeaderVariants(t *testing.T) {
	cases := []struct {
		in                                     string
		oldStart, oldCount, newStart, newCount int
		ok                                     bool
	}{
		{"@@ -1,5 +2,6 @@", 1, 5, 2, 6, true},
		{"@@ -1 +1 @@", 1, 1, 1, 1, true},
		{"@@ -0,0 +1,3 @@ func x()", 1, 0, 1, 3, true},
		{"@@ garbage @@", 0, 0, 0, 0, false},
		{"not a hunk", 0, 0, 0, 0, false},
	}
	for _, c := range cases {
		h, ok := parseHunkHeader(c.in)
		if ok != c.ok {
			t.Errorf("%q: ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if h.OldStart != c.oldStart || h.OldCount != c.oldCount ||
			h.NewStart != c.newStart || h.NewCount != c.newCount {
			t.Errorf("%q: got -%d,%d +%d,%d", c.in, h.OldStart, h.OldCount, h.NewStart, h.NewCount)
		}
	}
}

func TestParseNoNewlineMarker(t *testing.T) {
	patch := `--- a/x.txt
+++ b/x.txt
@@ -1 +1 @@
-old
\ No newline at end of file
+new
\ No newline at end of file
`
	d, err := ParseString(patch)
	if err != nil {
		t.Fatal(err)
	}
	f := d.Files[0]
	if f.Additions != 1 || f.Deletions != 1 {
		t.Errorf("additions/deletions = %d/%d", f.Additions, f.Deletions)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := ParseString(""); err != ErrEmpty {
		t.Errorf("err = %v, want ErrEmpty", err)
	}
	if _, err := ParseString("some commit message\nwith no patch\n"); err != ErrEmpty {
		t.Errorf("err = %v, want ErrEmpty", err)
	}
}

func TestTotals(t *testing.T) {
	d, err := ParseString(simplePatch + strings.Replace(simplePatch, "handler.go", "other.go", -1))
	if err != nil {
		t.Fatal(err)
	}
	files, adds, dels := d.Totals()
	if files != 2 || adds != 4 || dels != 2 {
		t.Errorf("totals = %d files, +%d, -%d", files, adds, dels)
	}
}

func TestExtAndBase(t *testing.T) {
	f := File{Path: "infra/modules/Network.TF"}
	if f.Ext() != ".tf" {
		t.Errorf("ext = %q", f.Ext())
	}
	if f.Base() != "Network.TF" {
		t.Errorf("base = %q", f.Base())
	}
}
