#!/bin/sh
# certbot DNS-01 cleanup hook: doğrulama bitince TXT değerlerini temizle.
rm -f /data/acme_challenge.txt
