package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

// A line is {"hash":"<64 hex>",<the event's JSON without its opening brace>. The hash covers
// those event bytes exactly as written, so verifying never depends on re-encoding them.
const hashPrefix = `{"hash":"`

func seal(e Event, key []byte) (line []byte, sum string, err error) {
	body, err := json.Marshal(e)
	if err != nil {
		return nil, "", err
	}
	sum = digest(key, body)
	line = append([]byte(hashPrefix+sum+`",`), body[1:]...)
	return line, sum, nil
}

func digest(key, body []byte) string {
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// open splits a sealed line into its hash and the event bytes it covers.
func open(line []byte) (sum string, body []byte, ok bool) {
	if !bytes.HasPrefix(line, []byte(hashPrefix)) || len(line) < len(hashPrefix)+66 {
		return "", nil, false
	}
	rest := line[len(hashPrefix):]
	if rest[64] != '"' || rest[65] != ',' {
		return "", nil, false
	}
	return string(rest[:64]), append([]byte("{"), rest[66:]...), true
}

// ChainReport describes one chain (one broker run) found in a log.
type ChainReport struct {
	Chain    string
	First    int64 // first seq seen
	Last     int64
	Problems []string
}

// Verify checks every ostiara audit line in r: each hash matches its event, each line points
// at the one before, and no line is missing. Other lines (e.g. operational logs) are skipped.
func Verify(r io.Reader, key []byte) ([]ChainReport, error) {
	type state struct {
		report *ChainReport
		prev   string
	}
	chains := map[string]*state{}
	var order []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if !bytes.Contains(line, []byte(`"stream":"`+Stream+`"`)) {
			continue
		}
		sum, body, ok := open(line)
		var e Event
		if !ok || json.Unmarshal(body, &e) != nil || e.Stream != Stream {
			st := chains[""]
			if st == nil {
				st = &state{report: &ChainReport{Chain: "(unchained)"}}
				chains[""], order = st, append(order, "")
			}
			st.report.Problems = append(st.report.Problems, fmt.Sprintf("line %d: audit event without a valid hash", n))
			continue
		}
		st := chains[e.Chain]
		if st == nil {
			st = &state{report: &ChainReport{Chain: e.Chain, First: e.Seq}}
			chains[e.Chain], order = st, append(order, e.Chain)
			if e.Seq != 1 {
				st.report.Problems = append(st.report.Problems, fmt.Sprintf("chain starts at seq %d: earlier lines are missing", e.Seq))
			}
		} else {
			if e.Seq != st.report.Last+1 {
				st.report.Problems = append(st.report.Problems, fmt.Sprintf("line %d: seq %d follows %d: lines missing or out of order", n, e.Seq, st.report.Last))
			}
			if e.Prev != st.prev {
				st.report.Problems = append(st.report.Problems, fmt.Sprintf("line %d (seq %d): doesn't follow the line before it", n, e.Seq))
			}
		}
		if !hmac.Equal([]byte(digest(key, body)), []byte(sum)) {
			st.report.Problems = append(st.report.Problems, fmt.Sprintf("line %d (seq %d): content was changed (hash doesn't match)", n, e.Seq))
		}
		st.report.Last, st.prev = e.Seq, sum
	}
	out := make([]ChainReport, 0, len(order))
	for _, c := range order {
		out = append(out, *chains[c].report)
	}
	return out, sc.Err()
}
