#!/usr/bin/env bash
# hunter-pentest alətlərini quraşdırır (Kali / Debian / Ubuntu).
# İstifadə:  bash install_tools.sh
set -u

echo "[*] hunter-pentest toolchain quraşdırılır..."

APT_PKGS=(nmap rustscan wpscan feroxbuster subfinder httpx katana nuclei gau seclists dirb)
GO_PKGS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/cmd/nuclei@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
)

have() { command -v "$1" >/dev/null 2>&1; }

# 1) apt ilə (Kali-də əksəri var)
if have apt-get; then
  echo "[*] apt paketləri: ${APT_PKGS[*]}"
  sudo apt-get update -y || true
  for p in "${APT_PKGS[@]}"; do
    if have "$p"; then
      echo "  [+] $p artıq var"
    else
      sudo apt-get install -y "$p" 2>/dev/null && echo "  [+] $p quraşdırıldı" \
        || echo "  [-] $p apt-də yoxdur (go fallback)"
    fi
  done
fi

# 2) go fallback — apt-də olmayan ProjectDiscovery alətləri
if ! have subfinder || ! have httpx || ! have katana || ! have nuclei || ! have gau; then
  if ! have go; then
    echo "[*] Go quraşdırılır..."
    sudo apt-get install -y golang-go 2>/dev/null || \
      echo "  [!] Go quraşdırılmadı — əl ilə: https://go.dev/dl/"
  fi
  if have go; then
    export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin"
    for pkg in "${GO_PKGS[@]}"; do
      name="$(basename "${pkg%%@*}")"
      if have "$name"; then
        echo "  [+] $name artıq var"
      else
        echo "  [*] go install $pkg"
        go install -v "$pkg" || echo "  [-] $name alınmadı"
      fi
    done
    # go/bin-i PATH-a əlavə et
    GOBIN="$(go env GOPATH 2>/dev/null)/bin"
    SHELL_RC="$HOME/.zshrc"; [ -f "$HOME/.bashrc" ] && [ ! -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.bashrc"
    if ! grep -q "$GOBIN" "$SHELL_RC" 2>/dev/null; then
      echo "export PATH=\"\$PATH:$GOBIN\"" >> "$SHELL_RC"
      echo "  [+] PATH yeniləndi ($SHELL_RC) — 'source $SHELL_RC' edin"
    fi
  fi
fi

# 3) nuclei şablonlarını yenilə
if have nuclei; then
  echo "[*] nuclei şablonları yenilənir..."
  nuclei -update-templates 2>/dev/null || true
fi

echo
echo "[*] Yekun vəziyyət:"
for t in subfinder httpx katana nuclei nmap rustscan wpscan feroxbuster gau; do
  if have "$t"; then echo "  [+] $t"; else echo "  [-] $t (yoxdur)"; fi
done
echo
echo "[i] WPScan vuln DB üçün pulsuz token: https://wpscan.com/register"
echo "    export WPSCAN_API_TOKEN=...  (~/.zshrc)"
echo "[i] Telegram bildirişi üçün: export TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=..."
echo "[*] Hazır. İndi: python3 hunter_pentest.py <domain> --i-have-authorization --mode full"
