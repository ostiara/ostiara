package notify

import (
	"context"
	"net/http"
	"strings"
)

// Slack posts to a Slack incoming webhook.
type Slack struct {
	URL    string
	Client *http.Client
}

func (Slack) Name() string { return "slack" }

func (s Slack) Send(ctx context.Context, e Event) error {
	return post(ctx, httpClient(s.Client), s.URL, map[string]string{"text": slackText(summarize(e))})
}

func slackText(m summary) string {
	var b strings.Builder
	b.WriteString("*" + slackEscape(m.Title) + "*\n")
	for _, f := range m.Facts {
		b.WriteString(f[0] + ": " + slackCode(f[1]) + "\n")
	}
	if m.Footer != "" {
		b.WriteString(slackCode(m.Footer) + "\n")
	}
	return b.String()
}

// slackEscape stops user text (a reason, a pod name) from becoming links or @channel pings.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackEscape(s string) string { return slackEscaper.Replace(s) }

// slackCode shows s literally, as inline code.
func slackCode(s string) string {
	return "`" + slackEscape(strings.ReplaceAll(s, "`", "'")) + "`"
}
