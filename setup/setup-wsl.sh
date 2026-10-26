#!/usr/bin/env bash
# php2shell-lab builder — Ubuntu 26.04 (works on 24.04/Debian 12+ with minor tweaks).
#
# Builds PHP 8.5.11 (last vulnerable 8.5 release) from source as an Apache mod_php
# module with stock settings, deploys the target app, and starts Apache on :8080.
#
# Root required. Idempotent: re-runs skip completed stages.
set -euo pipefail

PHP_VERSION="8.5.11"          # last vulnerable release; 8.5.12 contains the fix
BUILD_ROOT="/root/build"
PREFIX="/usr/local/php-${PHP_VERSION}"
TARGET_DIR="/var/www/php2shell-lab"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] php2shell-lab builder"
echo "    lab sources: ${LAB_DIR}"

# --- 1. toolchain + Apache ---------------------------------------------------
if ! command -v apxs2 >/dev/null 2>&1; then
    echo "[*] installing build deps + apache2"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential autoconf pkg-config bison re2c \
        libxml2-dev libsqlite3-dev apache2 apache2-dev \
        libcurl4-openssl-dev libssl-dev
fi

# --- 2. fetch + verify + extract + configure ---------------------------------
mkdir -p "${BUILD_ROOT}"
cd "${BUILD_ROOT}"

TARBALL="php-${PHP_VERSION}.tar.gz"
if [ ! -d "php-${PHP_VERSION}" ]; then
    echo "[*] downloading PHP ${PHP_VERSION} source"
    curl -sSL -o "${TARBALL}" "https://www.php.net/distributions/${TARBALL}"
    echo "    sha256: $(sha256sum "${TARBALL}" | cut -d' ' -f1)"
    tar xzf "${TARBALL}"
fi

if [ ! -f "php-${PHP_VERSION}/Makefile" ]; then
    echo "[*] configuring (mod_php via apxs2, defaults otherwise)"
    cd "php-${PHP_VERSION}"
    ./configure --with-apxs2=/usr/bin/apxs2 --disable-cgi --prefix="${PREFIX}" \
        > "${BUILD_ROOT}/configure.log" 2>&1
fi

# --- 3. build + install ------------------------------------------------------
if [ ! -f "${PREFIX}/lib/libphp.so" ] && [ ! -f "${PREFIX}/modules/libphp.so" ]; then
    echo "[*] compiling (nproc=$(nproc)) — 5-15 min"
    cd "${BUILD_ROOT}/php-${PHP_VERSION}"
    make -j"$(nproc)" > "${BUILD_ROOT}/build.log" 2>&1
    make install > "${BUILD_ROOT}/install.log" 2>&1
fi
LIBPHP="$(find "${PREFIX}" -name 'libphp*.so' | head -1)"
echo "[*] module: ${LIBPHP}"

# --- 4. php.ini (stock production values) ------------------------------------
mkdir -p "${PREFIX}/lib"
if [ ! -f "${PREFIX}/lib/php.ini" ]; then
    cp "${BUILD_ROOT}/php-${PHP_VERSION}/php.ini-production" "${PREFIX}/lib/php.ini"
    cat "${LAB_DIR}/setup/php-lab.ini" >> "${PREFIX}/lib/php.ini"
fi

# --- 5. target app ------------------------------------------------------------
mkdir -p "${TARGET_DIR}"
cp "${LAB_DIR}/target/index.php" "${TARGET_DIR}/index.php"

# --- 6. apache: prefork + mod_php + vhost -------------------------------------
a2dismod mpm_event >/dev/null 2>&1 || true
a2enmod mpm_prefork >/dev/null 2>&1

cat > /etc/apache2/mods-available/php2shell.load <<EOF
LoadModule php_module ${LIBPHP}
EOF
cat > /etc/apache2/mods-available/php2shell.conf <<EOF
AddType application/x-httpd-php .php
PHPIniDir "${PREFIX}/lib/"
EOF
a2enmod php2shell >/dev/null

cp "${LAB_DIR}/setup/apache-lab.conf" /etc/apache2/sites-available/php2shell-lab.conf
a2ensite php2shell-lab >/dev/null
a2dissite 000-default >/dev/null 2>&1 || true

# Small prefork pool: producer/consumer requests must land on the same worker.
CONF=/etc/apache2/mods-available/mpm_prefork.conf
if ! grep -q "php2shell-lab pool" "${CONF}" 2>/dev/null; then
    cat >> "${CONF}" <<EOF

# php2shell-lab pool: few workers so same-worker pinning is practical
StartServers            2
MinSpareServers         2
MaxSpareServers         4
MaxRequestWorkers       8
EOF
fi

# --- 7. go --------------------------------------------------------------------
echo "[*] starting apache"
apache2ctl configtest >/dev/null
apache2ctl start

echo "[*] waiting for listener"
for i in $(seq 1 20); do
    curl -s -o /dev/null "http://127.0.0.1:8080/" && break
    sleep 1
done

echo
echo "[+] lab up: http://127.0.0.1:8080/"
echo "[+] fingerprint:"
curl -s "http://127.0.0.1:8080/?action=info" | sed 's/^/    /'
echo
echo "[+] error log (watch here for worker segfaults):"
echo "    /var/log/apache2/php2shell-lab-error.log"
