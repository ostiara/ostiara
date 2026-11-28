package notify

import (
	"context"
	"net/http"
	"strings"
)

// Teams posts an Adaptive Card to a Teams Workflows webhook ("When a Teams webhook request is received").
type Teams struct {
	URL    string
	Client *http.Client
}

func (Teams) Name() string { return "teams" }

func (t Teams) Send(ctx context.Context, e Event) error {
	return post(ctx, httpClient(t.Client), t.URL, teamsCard(summarize(e)))
}

func teamsCard(m summary) map[string]any {
	facts := []map[string]string{}
	for _, f := range m.Facts {
		facts = append(facts, map[string]string{"title": f[0], "value": teamsEscape(f[1])})
	}
	body := []map[string]any{
		{"type": "TextBlock", "text": teamsEscape(m.Title), "weight": "Bolder", "wrap": true},
		{"type": "FactSet", "facts": facts},
	}
	if m.Footer != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": teamsEscape(m.Footer), "fontType": "Monospace", "wrap": true})
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    body,
			},
		}},
	}
}

// teamsEscape stops user text from turning into a Markdown link in the card. Cards show
// backslash escapes literally, so instead of escaping, it breaks the "[text](url)" pattern.
func teamsEscape(s string) string { return strings.ReplaceAll(s, "](", "] (") }
