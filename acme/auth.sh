#!/bin/sh
# certbot DNS-01 auth hook: doğrulama TXT değerini, Kanca DNS sunucusunun
# okuduğu paylaşımlı dosyaya yaz. (Wildcard sertifikada iki değer olabilir,
# bu yüzden ekleyerek yazıyoruz.)
echo "$CERTBOT_VALIDATION" >> /data/acme_challenge.txt
# DNS sunucusu dosyayı canlı okur; CA sorgusu için kısa güvenlik payı.
sleep 3
