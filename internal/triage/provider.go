package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	httpTimeout = 60 * time.Second
	maxTokens   = 1024
	maxRetries  = 1
)

// chatMessage is one OpenAI-compatible chat completion message.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest is the OpenAI-compatible request body; it also works for
// Gemini's OpenAI-compat endpoint, DeepSeek and GLM.
type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// anthropicRequest is the native Claude Messages API body.
type anthropicRequest struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	Messages  []chatMessage `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// complete sends one user prompt to the provider named in auth and returns
// the assistant text. Claude goes over the native Messages API; the rest
// speak the OpenAI-compatible chat protocol with per-provider base URLs.
func complete(ctx context.Context, auth *Auth, provider string, prompt string) (string, error) {
	pa, ok := auth.Providers[provider]
	if !ok || pa.APIKey == "" {
		return "", fmt.Errorf("no api key configured for provider %q", provider)
	}
	if pa.Model == "" {
		pa.Model = DefaultModels[provider]
	}
	if provider == Claude {
		return anthropicComplete(ctx, pa, prompt)
	}
	base := openAIBase
	switch provider {
	case Gemini:
		base = geminiBase
	case DeepSeek:
		base = deepSeekBase
	case GLM:
		base = glmBase
	}
	body, _ := json.Marshal(chatRequest{
		Model:     pa.Model,
		Messages:  []chatMessage{{Role: "user", Content: prompt}},
		MaxTokens: maxTokens,
	})
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		text, err := postJSON(ctx, base+"/chat/completions", pa.APIKey, body, false)
		if err == nil {
			return text, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("%s: %w", provider, lastErr)
}

func anthropicComplete(ctx context.Context, pa ProviderAuth, prompt string) (string, error) {
	body, _ := json.Marshal(anthropicRequest{
		Model:     pa.Model,
		MaxTokens: maxTokens,
		Messages:  []chatMessage{{Role: "user", Content: prompt}},
	})
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		text, err := postJSON(ctx, "https://api.anthropic.com/v1/messages", pa.APIKey, body, true)
		if err == nil {
			return text, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("claude: %w", lastErr)
}

func postJSON(ctx context.Context, url, apiKey string, body []byte, anthropic bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if anthropic {
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Del("Authorization")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	if anthropic {
		var ar anthropicResponse
		if err := json.Unmarshal(raw, &ar); err != nil {
			return "", fmt.Errorf("decode response: %w", err)
		}
		if ar.Error != nil {
			return "", fmt.Errorf("%s", ar.Error.Message)
		}
		if len(ar.Content) == 0 {
			return "", fmt.Errorf("empty response")
		}
		return ar.Content[0].Text, nil
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if cr.Error != nil {
		return "", fmt.Errorf("%s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("empty response")
	}
	return cr.Choices[0].Message.Content, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}
