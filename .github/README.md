# ⚙️ HDSD

1. Clone repository:

    ~~~ bash
    git clone https://github.com/CAOXUANHUY02/scanvirusandmerge.git
    cd scanvirusandmerge
    ~~~

2. Tạo file `.env` và thêm VirusTotal API key vafo:

    ~~~ env
    VT_API_KEY=virustotal_api_key
    ~~~

3. Chạy script cài đặt("Trong VPS, nên dùng Ubuntu 20.04 hoặc Debian 12"):

    ~~~ bash
    chmod +x setup.sh
    ./setup.sh
    ~~~

## API Endpoint

### Quét File

~~~ http
POST /
~~~

**Request:**

- Method: POST
- Content-Type: multipart/form-data
- Body: file (file ZIP, tối đa 32MB)

**Response:**

~~~ json
{
    "status": true, // true nếu file an toàn, false nếu phát hiện virus
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
~~~

Vấn đề Private hay không:

- [ĐỌC BÀI SAU](https://docs.virustotal.com/docs/accidental-upload)

### Xóa File Report

~~~ http
DELETE /delete/{file_hash}
~~~

**Request:**

- Method: DELETE
- Path parameter: file_hash (SHA-256 của file)

**Response:**

~~~ json
{
    "success": true
}
~~~

**Lưu ý:**

- Chức năng chỉ hoạt động với tài khoản có [Private Scanning license](https://docs.virustotal.com/docs/private-scanning#accessing-the-private-scanning-web-interface)
- file_hash là mã SHA-256 của file cần xóa
- SHA-256 được trả về trong response
