package hostcontext

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseModelReferences(t *testing.T) {
	cmd := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	tests := []struct {
		cmdline string
		want    []string
	}{
		{cmd("/usr/bin/python3", "-m", "vllm.entrypoints.openai.api_server", "--model", "/srv/models/Qwen", "--api-key", "SECRET"), []string{"srv/models/Qwen"}},
		{cmd("/opt/venv/bin/vllm", "serve", "Qwen/Qwen2-7B-Instruct", "--port", "8000"), []string{"Qwen/Qwen2-7B-Instruct"}},
		{cmd("/usr/local/bin/llama-server", "-m", "/models/q4.gguf", "--host", "0.0.0.0"), []string{"models/q4.gguf"}},
		{cmd("text-generation-launcher", "--model-id=org/model"), []string{"org/model"}},
		{cmd("/usr/bin/python3", "-m", "http.server", "--model", "/srv/x"), nil}, // not a model server
		{cmd("/opt/venv/bin/vllm", "serve", "--model", "/proc/1/root/x"), nil},   // denied path
	}
	for _, tt := range tests {
		if got := parseModelReferences(tt.cmdline, []string{"proc"}); !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%q: got %v want %v", tt.cmdline, got, tt.want)
		}
	}
}
