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

## Hızlı başlangıç (yerel / localhost)

Alt alan gerektirmeyen **path modu** ile saniyeler içinde denenir:

```bash
pip install -r requirements.txt
cp .env.example .env          # ADMIN_TOKEN'ı değiştir (CAPTURE_MODE=path zaten varsayılan)
uvicorn app.main:app --reload --port 8000
```
Panel: <http://localhost:8000> — anahtarı gir, "Oluştur" de, verilen
`http://localhost:8000/c/<token>/` adresine istek gönder; panelde anında görünür.

> Yerelde DNS yakalamayı denemek için `.env`'de `DNS_UDP_PORT=5353` yap ve
> `dig @127.0.0.1 -p 5353 test.<token>.oob.dagdelen.dev` ile sorgula.

## Üretim kurulumu (VPS, host modu)

Gerçek OOB (alt alan + DNS) için `.env`'de `CAPTURE_MODE=host` yap.

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

## Wildcard TLS (`*.oob`) — DNS-01

`oob` alt alanı kendi DNS sunucumuza delege olduğu için, Let's Encrypt
doğrulamasını (DNS-01) kendi sunucumuz yanıtlar — Cloudflare API'si gerekmez.
Kanca DNS sunucusu `_acme-challenge.{BASE_DOMAIN}` TXT sorgusunu, certbot auth
hook'unun `data/acme_challenge.txt`'ye yazdığı değerle yanıtlar.

Sertifikayı al (sıra önemli: önce kanca güncel çalışıyor olmalı):

```bash
docker compose run --rm certbot certonly \
  --manual --preferred-challenges dns \
  --manual-auth-hook "sh /hooks/auth.sh" \
  --manual-cleanup-hook "sh /hooks/cleanup.sh" \
  --cert-name oob -d "*.oob.alan.com" \
  --agree-tos -m you@example.com --non-interactive
```

Sonra Caddy'yi başlat (`*.oob`'u sertifikayla sunar) ve `.env`'de
`CAPTURE_SCHEME=https` yap:

```bash
docker compose up -d caddy
sed -i 's/^CAPTURE_SCHEME=.*/CAPTURE_SCHEME=https/' .env
docker compose up -d --force-recreate kanca
```

### Yenileme (90 günde bir)

Sertifika ~90 günde dolar. Haftalık cron ekle (`crontab -e`):

```
0 3 * * 1 cd /opt/kanca && docker compose run --rm certbot renew && docker compose restart caddy
```

`certbot renew` kayıtlı manual hook'ları yeniden çalıştırır; `restart caddy`
yeni sertifikayı yükler.
