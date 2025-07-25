echo "[*] Updating webdoxer..."



if [ ! -d "/opt/webdoxer" ]; then
git clone https://github.com/VulnVex/Webdoxer
fi

cd /opt/webdoxer || exit 1
pip install .

echo "[*] Update succesfull"
else
echo "[*] Error updating..."
