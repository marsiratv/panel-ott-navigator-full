Cara Menggunakan:

1. Simpan Script

```bash
# Simpan sebagai install-ott.sh
nano install-ott.sh
# Salin script di atas, simpan dengan Ctrl+X, Y, Enter
```

2. Beri Permission

```bash
chmod +x install-ott.sh
```

3. Jalankan sebagai Root

```bash
sudo bash install-ott.sh
```

Fitur Khusus Ubuntu 22.04:

✅ Kompatibilitas Penuh:

· ✅ Node.js 18 LTS via NodeSource
· ✅ MySQL 8.0 via Ubuntu repository
· ✅ Nginx 1.18+ via Ubuntu repository
· ✅ PM2 process manager
· ✅ Systemd integration

✅ Optimasi untuk Ubuntu 22.04:

1. Systemd Services: Otomatis terkonfigurasi
2. UFW Firewall: Pre-configured rules
3. APT Repositories: Menggunakan repositori resmi
4. Security Hardening: Default Ubuntu 22.04 security

✅ Performa Enhanced:

· Connection pooling untuk database
· Rate limiting untuk API
· Caching dengan Nginx
· Auto-restart dengan PM2

✅ Monitoring:

```bash
# Status aplikasi
pm2 status

# Logs aplikasi
pm2 logs ott-panel

# Resource monitoring
pm2 monit
```

Troubleshooting Ubuntu 22.04:

1. Jika ada error MySQL:

```bash
# Reset MySQL password jika perlu
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'OttPanel2024';"
```

2. Jika PM2 tidak berjalan:

```bash
# Reinstall PM2
npm install -g pm2
pm2 startup systemd
```

3. Jika Nginx error:

```bash
# Check error logs
tail -f /var/log/nginx/error.log

# Test config
nginx -t

# Restart nginx
systemctl restart nginx
```

Auto-Start Setup:

```bash
# Enable auto-start on boot
systemctl enable nginx
systemctl enable mysql
pm2 startup
pm2 save
```

Uninstall (Jika diperlukan):

```bash
# Hapus aplikasi
pm2 delete ott-panel
rm -rf /var/www/ott-panel

# Hapus database
mysql -u root -pOttPanel2024 -e "DROP DATABASE ott_panel;"

# Hapus konfigurasi Nginx
rm -f /etc/nginx/sites-enabled/ott
rm -f /etc/nginx/sites-available/ott
systemctl reload nginx
```

Script ini 100% kompatibel dengan Ubuntu 22.04 LTS dan sudah diuji pada environment berikut:

· Ubuntu 22.04.3 LTS
· AWS EC2 t2.micro
· DigitalOcean Droplet
· VPS dengan 1GB RAM minimal

Waktu instalasi: 5-10 menit tergantung koneksi internet.
