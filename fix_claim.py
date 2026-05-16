import re

with open('templates/claim_qr.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove qrcode.min.js
content = re.sub(r'<script src=.*qrcode\.min\.js.*></script>\s*', '', content)

# Replace window.onload
onload_new = '''    window.onload = function() {
      const params = new URLSearchParams(window.location.search);
      const itemId = params.get('item_id');
      const username = params.get('username');
      const qrData = encodeURIComponent(`TBX|${itemId}|${username}`);
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${qrData}&ecc=M`;
      
      document.getElementById("qr-code").innerHTML = `<img src="${qrUrl}" alt="QR Code" id="qr-img" style="display:block; margin:0 auto;">`;
    };'''

content = re.sub(r'    window\.onload = function\(\) \{[\s\S]*?\};\n', onload_new + '\n', content)

# Replace saveQRCode
save_new = '''    function saveQRCode() {
      const params = new URLSearchParams(window.location.search);
      const itemId = params.get('item_id');
      const username = params.get('username');
      const qrData = `TBX|${itemId}|${username}`;
      window.location.href = `/download_qr?data=${encodeURIComponent(qrData)}`;
    }'''

content = re.sub(r'    function saveQRCode\(\) \{[\s\S]*?\}\n', save_new + '\n', content)

with open('templates/claim_qr.html', 'w', encoding='utf-8') as f:
    f.write(content)
