# Kanca

Açık kaynak **out-of-band (OOB) etkileşim yakalama** aracı. Blind SSRF, XXE,
blind XSS ve OOB veri sızıntısı gibi zafiyetlerin **yetkili** testlerinde ve
siber güvenlik **eğitiminde**, dışarıya çıkan HTTP ve DNS etkileşimlerini
yakalar, kaydeder ve (opsiyonel) AI ile sınıflandırıp Telegram'a bildirir.

Aynı kategorideki araçlar: interactsh, Burp Collaborator.

> ⚠️ **Sorumluluk:** Yalnızca sahip olduğun veya açık test yetkisi aldığın
> sistemlere karşı, eğitim ve yetkili güvenlik testi amacıyla kullan. Kullanımın
> sorumluluğu sana aittir.

## Özellikler (v1)

- HTTP(S) ve DNS yakalama (tek process, asyncio)
- Her kanca için token tabanlı adres: `{token}.oob.alan.com`
- Mock motoru: özel status / header / body / gecikme
- SQLite (WAL) kalıcı depolama + geçmiş
- Canlı yayın (SSE, heartbeat'li)
- AI sınıflandırma (OpenAI uyumlu uç — Groq/OpenRouter/Ollama) + Telegram bildirimi
- Spam önleyici gruplama (aynı token için tek bildirim)
- [nopanic](https://github.com/dagdelenemre/nopanic) ile dayanıklı bildirim hattı

Sonraki aşama: SMTP/LDAP dinleyiciler, blind XSS probe üretici, panel arayüzü.

## Mimari

Ayrıntılar için [ARCHITECTURE.md](ARCHITECTURE.md).

## Kurulum

### 1. DNS / alan adı
`oob.alan.com` için VPS'ini gösteren bir **NS** kaydı ve glue **A** kaydı tanımla.
`panel.alan.com` için panel'in çalışacağı adrese **A** kaydı ver.

### 2. Yapılandırma
```bash
cp .env.example .env
# .env içini doldur: ADMIN_TOKEN, BASE_DOMAIN, PANEL_DOMAIN, PUBLIC_IP,
# ve isteğe bağlı AI_* / TELEGRAM_* anahtarları.
```

### 3. Çalıştırma
```bash
docker compose up -d
```
> Not: Konteyner 53 portunu dinler. Host'ta `systemd-resolved` 53'ü tutuyorsa
> devre dışı bırak. TLS için önüne nginx/Caddy koy (`*.oob.alan.com` için
> DNS-01 wildcard sertifikası).

### Geliştirme (yerel)
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Yerelde DNS için 53 yerine `.env`'de `DNS_UDP_PORT`/`DNS_TCP_PORT` değiştirilebilir.

## Kullanım

```bash
# Kanca oluştur
curl -X POST https://panel.alan.com/api/hooks \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"label":"test"}'
# → {"token":"...", "http_url":"https://<token>.oob.alan.com/", "dns_host":"<token>.oob.alan.com"}

# Etkileşimleri gör
curl https://panel.alan.com/api/interactions -H "X-Admin-Token: $ADMIN_TOKEN"

# Canlı yayın (EventSource header gönderemediği için token query ile)
#   https://panel.alan.com/api/stream?token=$ADMIN_TOKEN
```
