# Merge Blocklists

> [!NOTE]  
> This project was made for personal use, but others may use it too.


## ✨ What it does

- Fetches many public DNS blocklists  
- Removes comments & invalid rules  
- Normalizes and deduplicates entries  
- Keeps only rules compatible with AdGuard Home  
- Updates automatically every 12 hours via GitHub Actions  

---

## 🚀 Usage (AdGuard Home)

1. Open **AdGuard Home**
2. Go to **Filters → DNS blocklists**
3. Click **Add blocklist**
4. Paste this URL:

   ```text
   https://github.com/MissionWAR/Merge-Blocklists/releases/download/merged-latest/merged.txt
   ```

---

## 📚 Sources

All upstream filter URLs are stored in:

```
sources.txt
```

Each list is maintained by its original author.

---

## ⭐ Thanks

- **AdGuard Team** — inspiration for the idea  
- **Filterlist maintainers** — keeping lists alive  
- **Open-source community** — tools & documentation that made this possible

> [!CAUTION]  
> Please respect the licenses of the original blocklists if you fork or reuse this project.
