# DeserHunter: Yüksek Performanslı Deserialization Tarayıcısı

![Language](https://img.shields.io/badge/language-Go-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**DeserHunter**, büyük kod tabanlarında **Güvensiz Deserialization** (Insecure Deserialization) zafiyetlerini ışık hızında tespit etmek için tasarlanmış bir statik analiz güvenlik testi (SAST) aracıdır. Go ile yazılmıştır ve binlerce dosyayı saniyeler içinde taramak için eşzamanlılığı (concurrency) kullanır.

🔗 **GitHub Deposu:** [https://github.com/kaannsaydamm/DeserHunter](https://github.com/kaannsaydamm/DeserHunter)

## 🚀 Özellikler (Senior Level Features)
*   **Çoklu Dil Desteği:** Python, Java, PHP ve Node.js'deki tehlikeli desenleri tespit eder.
*   **Eşzamanlı Mimari:** Go rutinlerini (Worker Pool) kullanarak yüksek performanslı tarama yapar.
*   **Heuristic Taint Analysis (Akıllı Değişken Takibi):** Sabit stringler ("...") ile değişkenleri ($var) ayırt eder, yanlış alarmları (False Positive) düşürür.
*   **Magic Byte Detection (Sihirli Bayt Kontrolü):** Dosya uzantısına aldanmaz. İçeriğe (Magic Bytes) bakarak `.png` veya `.txt` içine gizlenmiş zararlı kodları bulur.
*   **Git Blame Entegrasyonu:** Zafiyetli kodu yazan kişiyi (Author) ve tarihi otomatik olarak rapora ekler.
*   **Obfuscation Scanner:** Şifrelenmiş payloadlar (Base64) veya şüpheli derecede karmaşık/uzun stringleri (Malware belirtisi) tespit eder.
*   **X-Ray Vision (Röntgen Görüşü):** `.jar`, `.war` ve `.zip` arşivlerinin içini bellekte (in-memory) tarar.
*   **Bağlam Farkındalığı (Context Awareness):** Bulguların etrafındaki kod satırlarını gösterir.
*   **SARIF & JSON Desteği:** GitHub Security Code Scanning ve CI/CD pipeline'ları için standart formatlarda raporlama yapar.

## 🛠 Kurulum & Kullanım

```bash
# Binary dosyasını derleyin
go build -o deserhunter .

# Bir projeyi tarayın (arşivler ve gizli dosyalar dahil)
./deserhunter --target /kaynak/kod/yolu

# SARIF formatında çıktı (GitHub Code Scanning için)
./deserhunter --target . --format sarif > results.sarif

# JSON formatında çıktı
./deserhunter --target . --format json > report.json
```

## 🛡️ Tespit Yetenekleri

-   **Python:** pickle, yaml.load, marshal
-   **Java:** ObjectInputStream, XMLDecoder (JAR içi analiz)
-   **PHP:** unserialize, phar://, obfuscated eval(base64...)
-   **Node.js:** node-serialize (IIFE üzerinden RCE)

## ⚠️ Sorumluluk Reddi (Disclaimer)

Bu araç yalnızca güvenlik araştırmaları ve yetkili denetim amaçları için tasarlanmıştır.

---
Made By Kaan Saydam, 2026.