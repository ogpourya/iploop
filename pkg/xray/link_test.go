package xray

import (
	"encoding/json"
	"testing"
)

func TestParseVless(t *testing.T) {
	link := "vless://7221b5ec-dcd6-4564-aba0-90fe657c6608@91.199.43.205:443?encryption=none&security=tls&sni=ultra.539.qzz.io&fp=chrome&alpn=h2%2Chttp%2F1.1&insecure=0&allowInsecure=0&type=ws&host=ultra.539.qzz.io&path=%2F27a342b5896d#tg8450765301_caf5f7cd"
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if ob.Protocol != "vless" {
		t.Fatalf("expected vless, got %s", ob.Protocol)
	}
	if ob.Tag != "tg8450765301_caf5f7cd" {
		t.Fatalf("expected tg8450765301_caf5f7cd, got %s", ob.Tag)
	}
	settings := ob.Settings
	if settings["id"] != "7221b5ec-dcd6-4564-aba0-90fe657c6608" {
		t.Fatalf("bad id: %v", settings["id"])
	}
	if settings["address"] != "91.199.43.205" {
		t.Fatalf("bad address: %v", settings["address"])
	}
	stream := ob.StreamSettings
	if stream["network"] != "ws" {
		t.Fatalf("bad network: %v", stream["network"])
	}
	if stream["security"] != "tls" {
		t.Fatalf("bad security: %v", stream["security"])
	}
	ws := stream["wsSettings"].(map[string]any)
	if ws["path"] != "/27a342b5896d" {
		t.Fatalf("bad ws path: %v", ws["path"])
	}
	if ws["host"] != "ultra.539.qzz.io" {
		t.Fatalf("bad ws host: %v", ws["host"])
	}
	tls := stream["tlsSettings"].(map[string]any)
	if tls["serverName"] != "ultra.539.qzz.io" {
		t.Fatalf("bad sni: %v", tls["serverName"])
	}
}

func TestParseVmess(t *testing.T) {
	link := "vmess://eyJhZGQiOiIxOTIuMTY4LjEuMSIsInBvcnQiOiI0NDMiLCJpZCI6IjcyMjFiNWVjLWRjZDYtNDU2NC1hYmEwLTkwZmU2NTdjNjYwOCIsIm5ldCI6IndzIiwidGxzIjoidGxzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii92bWVzcyIsInBzIjoibXktdm1lc3MifQ=="
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if ob.Protocol != "vmess" {
		t.Fatalf("expected vmess, got %s", ob.Protocol)
	}
	if ob.Tag != "my-vmess" {
		t.Fatalf("expected my-vmess, got %s", ob.Tag)
	}
}

func TestParseVmessInsecure(t *testing.T) {
	link := "vmess://eyJhZGQiOiIxOTIuMTY4LjEuMSIsInBvcnQiOiI0NDMiLCJpZCI6IjcyMjFiNWVjLWRjZDYtNDU2NC1hYmEwLTkwZmU2NTdjNjYwOCIsIm5ldCI6IndzIiwidGxzIjoidGxzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii92bWVzcyIsInBzIjoibXktdm1lc3MiLCJpbnNlY3VyZSI6IjEifQ=="
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	tls := ob.StreamSettings["tlsSettings"].(map[string]any)
	if tls["insecure"] != true {
		t.Fatal("expected insecure=true")
	}
}

func TestParseVlessInsecure(t *testing.T) {
	link := "vless://uuid@host:443?security=tls&type=tcp&insecure=1&allowInsecure=true#test"
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	tls := ob.StreamSettings["tlsSettings"].(map[string]any)
	if tls["insecure"] != true {
		t.Fatal("expected insecure=true")
	}
	if tls["allowInsecure"] != true {
		t.Fatal("expected allowInsecure=true")
	}
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://password123@example.com:443?security=tls&type=tcp&sni=example.com#my-trojan"
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if ob.Protocol != "trojan" {
		t.Fatalf("expected trojan, got %s", ob.Protocol)
	}
}

func TestParseShadowsocks(t *testing.T) {
	link := "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443#my-ss"
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}
	if ob.Protocol != "shadowsocks" {
		t.Fatalf("expected shadowsocks, got %s", ob.Protocol)
	}
}

func TestConfigGeneration(t *testing.T) {
	link := "vless://7221b5ec-dcd6-4564-aba0-90fe657c6608@91.199.43.205:443?encryption=none&security=tls&sni=ultra.539.qzz.io&fp=chrome&alpn=h2%2Chttp%2F1.1&type=ws&host=ultra.539.qzz.io&path=%2F27a342b5896d#tg8450765301_caf5f7cd"
	ob, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink failed: %v", err)
	}

	config := buildConfig([]*entry{
		{outbound: ob, port: 55555, tag: ob.Tag},
	})

	j, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(j, &parsed); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	log, ok := parsed["log"].(map[string]any)
	if !ok || log["loglevel"] != "warning" {
		t.Fatal("expected log.warning")
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatal("expected 1 inbound")
	}
	inb := inbounds[0].(map[string]any)
	if inb["protocol"] != "socks" {
		t.Fatal("expected socks inbound")
	}
	if inb["port"] != float64(55555) {
		t.Fatal("expected port 55555")
	}

	outbounds, ok := parsed["outbounds"].([]any)
	if !ok || len(outbounds) != 2 {
		t.Fatal("expected 2 outbounds")
	}
	outb := outbounds[0].(map[string]any)
	if outb["protocol"] != "vless" {
		t.Fatal("expected vless outbound")
	}

	dnsOut := outbounds[1].(map[string]any)
	if dnsOut["protocol"] != "dns" {
		t.Fatal("expected dns outbound")
	}

	routing, ok := parsed["routing"].(map[string]any)
	if !ok {
		t.Fatal("expected routing")
	}
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatal("expected 1 routing rule")
	}
}
