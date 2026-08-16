package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type CertEntry struct {
	ID           int64  `json:"id,string"` // 用字符串传输，防止前端精度丢失
	Type         string `json:"type"`      // "ca" 或 "server"
	Name         string `json:"name"`
	Country      string `json:"country,omitempty"`
	State        string `json:"state,omitempty"`
	Locality     string `json:"locality,omitempty"`
	Organization string `json:"org,omitempty"`
	Unit         string `json:"ou,omitempty"`
	Email        string `json:"email,omitempty"`
	KeyFile      string `json:"key"`  // 相对路径 certs/xxx/key.pem
	CertFile     string `json:"crt"`
	CreatedAt    string `json:"time"`
	Days         int    `json:"days,omitempty"` // 有效期天数
}

var (
	dataFile string
	certDir  string
)

func main() {
	port := "8080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	execDir, _ := os.Getwd()
	certDir = filepath.Join(execDir, "certs")
	os.MkdirAll(certDir, 0755)

	dataFile = filepath.Join(execDir, "certs.json")
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		os.WriteFile(dataFile, []byte("[]"), 0644)
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/list", handleList)
	http.HandleFunc("/api/gen-ca", handleGenCA)
	http.HandleFunc("/api/issue", handleIssue)
	http.HandleFunc("/api/download", handleDownload)
	http.HandleFunc("/api/view", handleViewKey)
	http.HandleFunc("/api/delete", handleDelete) // 删除接口

	fmt.Printf("证书管家已启动 : http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": msg})
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func safeDirName(prefix, name string, id int64) string {
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	return fmt.Sprintf("%s_%s_%d", prefix, clean, id)
}

func loadEntries() []CertEntry {
	data, _ := os.ReadFile(dataFile)
	var entries []CertEntry
	json.Unmarshal(data, &entries)
	return entries
}

func saveEntries(entries []CertEntry) {
	b, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(dataFile, b, 0644)
}

func writePem(path, pemType string, derBytes []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: derBytes})
}

// 页面
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, htmlPage)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := loadEntries()
	b, _ := json.Marshal(entries)
	w.Write(b)
}

// ========== 生成 CA ==========
func handleGenCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "仅支持 POST", 405)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req struct {
		Name         string `json:"name"`
		Country      string `json:"country"`
		State        string `json:"state"`
		Locality     string `json:"locality"`
		Organization string `json:"org"`
		Unit         string `json:"ou"`
		Email        string `json:"email"`
		Days         string `json:"days"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, "JSON 格式错误", 400)
		return
	}

	if req.Name == "" {
		req.Name = "My Root CA"
	}
	if req.Country == "" {
		req.Country = "CN"
	}
	if req.State == "" {
		req.State = "Beijing"
	}
	if req.Locality == "" {
		req.Locality = "Beijing"
	}
	if req.Organization == "" {
		req.Organization = "My Org"
	}
	if req.Unit == "" {
		req.Unit = "IT"
	}

	days := 3650
	if req.Days != "" {
		if v, err := strconv.Atoi(req.Days); err == nil && v > 0 {
			days = v
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		jsonError(w, "生成私钥失败: "+err.Error(), 500)
		return
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.Name,
			Country:            []string{req.Country},
			Province:           []string{req.State},
			Locality:           []string{req.Locality},
			Organization:       []string{req.Organization},
			OrganizationalUnit: []string{req.Unit},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	if req.Email != "" {
		tmpl.EmailAddresses = []string{req.Email}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		jsonError(w, "签发 CA 证书失败: "+err.Error(), 500)
		return
	}

	id := time.Now().UnixNano()
	subDir := safeDirName("CA", req.Name, id)
	dir := filepath.Join(certDir, subDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		jsonError(w, "创建目录失败: "+err.Error(), 500)
		return
	}

	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	if err := writePem(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv)); err != nil {
		jsonError(w, "保存私钥失败: "+err.Error(), 500)
		return
	}
	if err := writePem(certPath, "CERTIFICATE", certDER); err != nil {
		jsonError(w, "保存证书失败: "+err.Error(), 500)
		return
	}

	entry := CertEntry{
		ID:           id,
		Type:         "ca",
		Name:         req.Name,
		Country:      req.Country,
		State:        req.State,
		Locality:     req.Locality,
		Organization: req.Organization,
		Unit:         req.Unit,
		Email:        req.Email,
		KeyFile:      filepath.Join(subDir, "ca.key"),
		CertFile:     filepath.Join(subDir, "ca.crt"),
		CreatedAt:    time.Now().Format(time.RFC3339),
		Days:         days,
	}

	entries := loadEntries()
	entries = append(entries, entry)
	saveEntries(entries)

	fmt.Printf("[CA] 生成成功: %s (ID=%d, %d天)\n", entry.Name, entry.ID, days)
	jsonOK(w, map[string]interface{}{"ok": true, "ca": entry})
}

// ========== 签发域名证书 ==========
func handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "仅支持 POST", 405)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var req struct {
		CAID         string `json:"caId"`
		Domain       string `json:"domain"`
		AltDNS       string `json:"alt"`
		Country      string `json:"country"`
		State        string `json:"state"`
		Locality     string `json:"locality"`
		Organization string `json:"org"`
		Unit         string `json:"ou"`
		Email        string `json:"email"`
		Days         string `json:"days"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, "JSON 格式错误: "+err.Error(), 400)
		return
	}
	if req.Domain == "" {
		jsonError(w, "域名不能为空", 400)
		return
	}

	var caID int64
	if _, err := fmt.Sscanf(req.CAID, "%d", &caID); err != nil {
		jsonError(w, "CAID 格式错误", 400)
		return
	}

	days := 398
	if req.Days != "" {
		if v, err := strconv.Atoi(req.Days); err == nil && v > 0 {
			days = v
		}
	}

	fmt.Printf("[Issue] 请求: domain=%s, CAID=%d, %d天\n", req.Domain, caID, days)

	entries := loadEntries()
	var caEntry *CertEntry
	for i := range entries {
		if entries[i].ID == caID && entries[i].Type == "ca" {
			caEntry = &entries[i]
			break
		}
	}
	if caEntry == nil {
		fmt.Printf("[Issue] 错误: 未找到 CA (ID=%d)\n", caID)
		jsonError(w, fmt.Sprintf("未找到 CA (ID=%d)", caID), 404)
		return
	}

	// 读取 CA 私钥
	caKeyPath := filepath.Join(certDir, caEntry.KeyFile)
	caKeyPEM, _ := os.ReadFile(caKeyPath)
	caBlock, _ := pem.Decode(caKeyPEM)
	caPriv, _ := x509.ParsePKCS1PrivateKey(caBlock.Bytes)

	// 读取 CA 证书
	caCrtPath := filepath.Join(certDir, caEntry.CertFile)
	caCrtPEM, _ := os.ReadFile(caCrtPath)
	caCrtBlock, _ := pem.Decode(caCrtPEM)
	caCert, _ := x509.ParseCertificate(caCrtBlock.Bytes)

	serverPriv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// 继承 CA 信息
	country := req.Country
	if country == "" {
		country = caEntry.Country
	}
	state := req.State
	if state == "" {
		state = caEntry.State
	}
	locality := req.Locality
	if locality == "" {
		locality = caEntry.Locality
	}
	org := req.Organization
	if org == "" {
		org = caEntry.Organization
	}
	unit := req.Unit
	if unit == "" {
		unit = caEntry.Unit
	}
	email := req.Email
	if email == "" {
		email = caEntry.Email
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         req.Domain,
			Country:            []string{country},
			Province:           []string{state},
			Locality:           []string{locality},
			Organization:       []string{org},
			OrganizationalUnit: []string{unit},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, days),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	if email != "" {
		tmpl.EmailAddresses = []string{email}
	}

	tmpl.DNSNames = append(tmpl.DNSNames, req.Domain)
	if req.AltDNS != "" {
		for _, d := range strings.Split(req.AltDNS, ",") {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if ip := net.ParseIP(d); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, d)
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		fmt.Printf("[Issue] 错误: 签发失败: %v\n", err)
		jsonError(w, "签发失败: "+err.Error(), 500)
		return
	}

	id := time.Now().UnixNano()
	subDir := safeDirName("server", req.Domain, id)
	dir := filepath.Join(certDir, subDir)
	os.MkdirAll(dir, 0755)

	keyPath := filepath.Join(dir, "server.key")
	certPath := filepath.Join(dir, "server.crt")
	writePem(keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPriv))
	writePem(certPath, "CERTIFICATE", certDER)

	entry := CertEntry{
		ID:           id,
		Type:         "server",
		Name:         req.Domain,
		Country:      country,
		State:        state,
		Locality:     locality,
		Organization: org,
		Unit:         unit,
		Email:        email,
		KeyFile:      filepath.Join(subDir, "server.key"),
		CertFile:     filepath.Join(subDir, "server.crt"),
		CreatedAt:    time.Now().Format(time.RFC3339),
		Days:         days,
	}

	entries = loadEntries()
	entries = append(entries, entry)
	saveEntries(entries)

	fmt.Printf("[Issue] 签发成功: %s -> %s (%d天)\n", req.Domain, dir, days)
	jsonOK(w, map[string]interface{}{"ok": true, "cert": entry})
}

// ========== 删除证书/CA ==========
func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		jsonError(w, "仅支持 DELETE", 405)
		return
	}

	// 从查询参数获取 id
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		jsonError(w, "缺少 id 参数", 400)
		return
	}

	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		jsonError(w, "id 格式错误", 400)
		return
	}

	entries := loadEntries()
	var target *CertEntry
	var idx int
	for i := range entries {
		if entries[i].ID == id {
			target = &entries[i]
			idx = i
			break
		}
	}
	if target == nil {
		jsonError(w, "未找到对应条目", 404)
		return
	}

	// 删除文件
	keyPath := filepath.Join(certDir, target.KeyFile)
	crtPath := filepath.Join(certDir, target.CertFile)
	os.Remove(keyPath)
	os.Remove(crtPath)

	// 如果是 CA，删除可能存在的 serial 文件
	if target.Type == "ca" {
		// 证书目录
		dir := filepath.Dir(keyPath)
		os.RemoveAll(dir) // 删除整个 CA 目录（里面只有这两个文件）
	} else {
		// 域名证书目录
		dir := filepath.Dir(keyPath)
		os.RemoveAll(dir) // 删除整个目录
	}

	// 从数据库删除
	entries = append(entries[:idx], entries[idx+1:]...)
	saveEntries(entries)

	fmt.Printf("[Delete] 已删除: %s (ID=%d)\n", target.Name, target.ID)
	jsonOK(w, map[string]interface{}{"ok": true, "id": id})
}

// ========== 下载文件 ==========
func handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("f")
	if filename == "" {
		http.Error(w, "missing file", 400)
		return
	}
	fullPath := filepath.Join(certDir, filename)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.Error(w, "文件不存在", 404)
		return
	}
	data, _ := os.ReadFile(fullPath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filename)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// ========== 查看文件内容 ==========
func handleViewKey(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("f")
	if filename == "" {
		http.Error(w, "missing file", 400)
		return
	}
	fullPath := filepath.Join(certDir, filename)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "文件不存在", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

// ========== 前端页面 (内嵌) ==========
const htmlPage = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>证书管家</title>
<style>
:root {
  --primary: #4f46e5;
  --primary-hover: #4338ca;
  --success: #059669;
  --danger: #dc2626;
  --bg: #f3f4f6;
  --card: #ffffff;
  --text: #1f2937;
  --border: #e5e7eb;
  --radius: 8px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 20px; max-width: 900px; margin: 0 auto; }
.card { background: var(--card); padding: 24px; border-radius: var(--radius); box-shadow: 0 1px 3px rgba(0,0,0,0.06); margin-bottom: 24px; }
h2 { font-size: 1.4rem; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
h3 { font-size: 1.1rem; margin-bottom: 12px; }
.form-row { display: flex; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.field { flex: 1 1 200px; }
.field label { display: block; font-size: 0.85rem; margin-bottom: 4px; color: #4b5563; }
.field input { width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: var(--radius); font-size: 0.95rem; }
button { padding: 10px 18px; border: none; border-radius: var(--radius); font-size: 0.9rem; font-weight: 500; cursor: pointer; transition: background 0.2s; }
.btn-primary { background: var(--primary); color: #fff; }
.btn-primary:hover { background: var(--primary-hover); }
.btn-success { background: var(--success); color: #fff; }
.btn-success:hover { background: #047857; }
.btn-outline { background: #fff; border: 1px solid var(--border); color: var(--text); margin-left: 6px; }
.btn-outline:hover { background: #f9fafb; }
.btn-sm { padding: 6px 12px; font-size: 0.8rem; }
.btn-danger { background: var(--danger); color: #fff; }
.btn-danger:hover { background: #b91c1c; }
.cert-item { display: flex; align-items: center; padding: 10px 14px; border: 1px solid var(--border); border-radius: var(--radius); margin-bottom: 8px; gap: 12px; flex-wrap: wrap; }
.cert-item .info { flex: 1; min-width: 200px; }
.cert-item .actions { display: flex; gap: 6px; flex-wrap: wrap; }
.tag { background: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 20px; font-size: 0.7rem; margin-left: 8px; }
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.4); justify-content: center; align-items: center; z-index: 1000; }
.modal-content { background: #fff; border-radius: 12px; padding: 20px; max-width: 750px; width: 90%; max-height: 80vh; display: flex; flex-direction: column; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.modal-header h3 { margin-bottom: 0; }
.modal-body { flex: 1; overflow-y: auto; }
.modal-body pre { background: #1e1e2e; color: #e5e7eb; padding: 16px; border-radius: 6px; font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; max-height: 50vh; overflow-y: auto; }
.close-btn { background: none; border: none; font-size: 1.5rem; cursor: pointer; }
.copy-btn { margin-top: 10px; background: var(--primary); color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
.toast { position: fixed; top: 20px; right: 20px; padding: 12px 20px; border-radius: 8px; color: #fff; z-index: 1100; display: none; max-width: 400px; }
.toast.success { background: var(--success); }
.toast.error { background: var(--danger); }
</style>
</head>
<body>
<h2>🔐 证书管家</h2>

<div class="card">
  <h3>🏛️ 创建根证书 (CA)</h3>
  <div class="form-row">
    <div class="field"><label>通用名称 *</label><input id="caName" value="My Root CA"></div>
    <div class="field"><label>有效期 (天)</label><input id="caDays" value="3650" type="number"></div>
  </div>
  <div class="form-row">
    <div class="field"><label>国家</label><input id="caCountry" value="CN"></div>
    <div class="field"><label>省/州</label><input id="caState" value="Beijing"></div>
    <div class="field"><label>城市</label><input id="caLocality" value="Beijing"></div>
  </div>
  <div class="form-row">
    <div class="field"><label>组织</label><input id="caOrg" value="My Organization"></div>
    <div class="field"><label>部门</label><input id="caOU" value="IT Department"></div>
    <div class="field"><label>邮箱</label><input id="caEmail" value="admin@example.com"></div>
  </div>
  <button class="btn-primary" onclick="genCA()">⚡ 生成 CA</button>
</div>

<div id="caList"></div>

<div class="card" id="issueCard" style="display:none">
  <h3>📄 签发域名证书</h3>
  <p id="selectedCA" style="margin-bottom:12px; font-size:0.9rem; color:#4b5563;"></p>
  <div class="form-row">
    <div class="field"><label>域名 *</label><input id="certDomain" value="myapp.local"></div>
    <div class="field"><label>有效期 (天)</label><input id="certDays" value="398" type="number"></div>
  </div>
  <div class="form-row">
    <div class="field"><label>附加域名 (逗号分隔)</label><input id="certAlt" placeholder="*.myapp.local, 127.0.0.1"></div>
  </div>
  <div class="form-row">
    <div class="field"><label>国家</label><input id="certCountry" placeholder="继承 CA"></div>
    <div class="field"><label>省/州</label><input id="certState" placeholder="继承 CA"></div>
    <div class="field"><label>城市</label><input id="certLocality" placeholder="继承 CA"></div>
  </div>
  <div class="form-row">
    <div class="field"><label>组织</label><input id="certOrg" placeholder="继承 CA"></div>
    <div class="field"><label>部门</label><input id="certOU" placeholder="继承 CA"></div>
    <div class="field"><label>邮箱</label><input id="certEmail" placeholder="继承 CA"></div>
  </div>
  <button class="btn-success" onclick="issueCert()">✅ 签发证书</button>
</div>

<div id="certList"></div>

<div id="viewModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="modalTitle">内容查看</h3>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body">
      <pre id="modalContent"></pre>
      <button class="copy-btn" onclick="copyContent()">📋 复制内容</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
let entries = [], selectedCAId = null;

async function loadData() {
  try {
    const res = await fetch('/api/list');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    entries = await res.json();
    renderLists();
  } catch(e) {
    showToast('加载数据失败: ' + e.message, true);
  }
}

function renderLists() {
  const caList = document.getElementById('caList');
  const certList = document.getElementById('certList');
  let caHtml = '', certHtml = '';

  entries.forEach(e => {
    if (e.type === 'ca') {
      caHtml += '<div class="cert-item">' +
        '<div class="info"><strong>' + esc(e.name) + '</strong> <span class="tag">CA</span><br>' +
        '<small style="color:#6b7280">' + (e.country||'') + ' ' + (e.state||'') + ' | ' + (e.email||'') + ' | ' + (e.days ? e.days+'天' : '') + '</small></div>' +
        '<div class="actions">' +
        '<button class="btn-outline btn-sm" onclick="useCA(\'' + e.id + '\')">📄 签发</button>' +
        '<button class="btn-outline btn-sm" onclick="viewContent(\'' + e.crt + '\')">📜 证书</button>' +
        '<button class="btn-outline btn-sm" onclick="viewContent(\'' + e.key + '\')">🔑 私钥</button>' +
        '<a class="btn-outline btn-sm" href="/api/download?f=' + encodeURIComponent(e.crt) + '" download>⬇️ 证书</a>' +
        '<a class="btn-outline btn-sm" href="/api/download?f=' + encodeURIComponent(e.key) + '" download>⬇️ 私钥</a>' +
        '<button class="btn-danger btn-sm" onclick="deleteEntry(\'' + e.id + '\')">🗑️ 删除</button>' +
        '</div></div>';
    } else {
      certHtml += '<div class="cert-item">' +
        '<div class="info"><strong>' + esc(e.name) + '</strong> <span class="tag">域名证书</span><br>' +
        '<small style="color:#6b7280">' + (e.days ? '有效期 '+e.days+' 天' : '') + '</small></div>' +
        '<div class="actions">' +
        '<button class="btn-outline btn-sm" onclick="viewContent(\'' + e.crt + '\')">📜 证书</button>' +
        '<button class="btn-outline btn-sm" onclick="viewContent(\'' + e.key + '\')">🔑 私钥</button>' +
        '<a class="btn-outline btn-sm" href="/api/download?f=' + encodeURIComponent(e.crt) + '" download>⬇️ 证书</a>' +
        '<a class="btn-outline btn-sm" href="/api/download?f=' + encodeURIComponent(e.key) + '" download>⬇️ 私钥</a>' +
        '<button class="btn-danger btn-sm" onclick="deleteEntry(\'' + e.id + '\')">🗑️ 删除</button>' +
        '</div></div>';
    }
  });

  if (!caHtml) caHtml = '<p style="color:#9ca3af; padding:10px">暂无根证书，请先创建一个。</p>';
  if (!certHtml) certHtml = '<p style="color:#9ca3af; padding:10px">暂无域名证书。</p>';

  caList.innerHTML = caHtml;
  certList.innerHTML = certHtml;
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}

function useCA(id) {
  selectedCAId = id;
  const ca = entries.find(e => e.id === id);
  document.getElementById('selectedCA').textContent = '当前 CA: ' + ca.name + ' (ID=' + id + ')';
  document.getElementById('issueCard').style.display = 'block';
}

async function genCA() {
  const name = document.getElementById('caName').value.trim();
  if (!name) return alert('请输入 CA 名称');
  const body = {
    name,
    days: document.getElementById('caDays').value.trim() || "3650",
    country: document.getElementById('caCountry').value.trim(),
    state: document.getElementById('caState').value.trim(),
    locality: document.getElementById('caLocality').value.trim(),
    org: document.getElementById('caOrg').value.trim(),
    ou: document.getElementById('caOU').value.trim(),
    email: document.getElementById('caEmail').value.trim()
  };
  try {
    const res = await fetch('/api/gen-ca', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.ok) {
      showToast('CA 生成成功');
      entries.push(data.ca);
      renderLists();
    } else {
      alert('生成失败: ' + (data.error || res.statusText));
      showToast('生成失败', true);
    }
  } catch(e) {
    alert('请求异常: ' + e.message);
    showToast('请求异常', true);
  }
}

async function issueCert() {
  if (!selectedCAId) return alert('请先点击 CA 的“签发”按钮');
  const domain = document.getElementById('certDomain').value.trim();
  if (!domain) return alert('请输入域名');
  const body = {
    caId: selectedCAId,
    domain,
    alt: document.getElementById('certAlt').value.trim(),
    days: document.getElementById('certDays').value.trim() || "398",
    country: document.getElementById('certCountry').value.trim(),
    state: document.getElementById('certState').value.trim(),
    locality: document.getElementById('certLocality').value.trim(),
    org: document.getElementById('certOrg').value.trim(),
    ou: document.getElementById('certOU').value.trim(),
    email: document.getElementById('certEmail').value.trim()
  };
  try {
    const res = await fetch('/api/issue', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const data = await res.json();
    if (data.ok && data.cert) {
      showToast('签发成功');
      entries.push(data.cert);
      renderLists();
    } else {
      alert('签发失败: ' + (data.error || res.statusText));
      showToast('签发失败', true);
    }
  } catch(e) {
    alert('请求异常: ' + e.message);
    showToast('请求异常', true);
  }
}

async function deleteEntry(id) {
  if (!confirm('确定要删除吗？相关文件将永久删除。')) return;
  try {
    const res = await fetch('/api/delete?id=' + id, { method: 'DELETE' });
    const data = await res.json();
    if (data.ok) {
      showToast('已删除');
      entries = entries.filter(e => e.id !== id);
      renderLists();
    } else {
      alert('删除失败: ' + (data.error || ''));
    }
  } catch(e) {
    alert('请求异常: ' + e.message);
  }
}

async function viewContent(filename) {
  document.getElementById('modalTitle').textContent = filename;
  try {
    const res = await fetch('/api/view?f=' + encodeURIComponent(filename));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const content = await res.text();
    document.getElementById('modalContent').textContent = content;
    document.getElementById('viewModal').style.display = 'flex';
  } catch(e) {
    showToast('无法读取文件: ' + e.message, true);
  }
}

function closeModal() { document.getElementById('viewModal').style.display = 'none'; }

function copyContent() {
  const text = document.getElementById('modalContent').textContent;
  navigator.clipboard.writeText(text).then(() => showToast('已复制'))
    .catch(() => {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('已复制');
    });
}

function showToast(msg, isError = false) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast ' + (isError ? 'error' : 'success');
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 4000);
}

document.getElementById('viewModal').addEventListener('click', function(e) {
  if (e.target === this) closeModal();
});

loadData();
</script>
</body>
</html>`