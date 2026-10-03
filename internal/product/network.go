package product

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/optimize"
	"io"
	"net"
	"net/http"
)

func Address(n model.Node) (string, error) {
	ip, err := diagnostic.TargetIP(&model.Peer{Node: n})
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(Port)), nil
}
func call(ctx context.Context, address, path string, input, output any) error {
	method := http.MethodGet
	var body io.Reader
	if input != nil {
		method = http.MethodPost
		data, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(data)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://"+address+path, body)
	if e != nil {
		return e
	}
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	resp, e := (&http.Client{Transport: tr}).Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, data)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(output)
}
func Discover(ctx context.Context, n model.Node) (string, optimize.ProductInfo, error) {
	var info optimize.ProductInfo
	address, e := Address(n)
	if e != nil {
		return "", info, e
	}
	e = call(ctx, address, "/product/v1/info", nil, &info)
	if e == nil && (info.Protocol != 1 || info.SelfID != n.ID || info.Product != Name) {
		e = errors.New("对端产品协议或节点身份不匹配")
	}
	return address, info, e
}
