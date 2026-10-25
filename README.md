# Landing page THPT Bình Gia (có đăng nhập và tải ảnh)

## Chạy thử

1. Cài Node.js phiên bản 18 trở lên.
2. Trong thư mục này, chạy `npm install`.
3. Chạy `ADMIN_USERNAME=quantri npm start`
   (PowerShell trên Windows: `$env:ADMIN_USERNAME="quantri"; npm start`).
4. Mở http://localhost:3000. Đừng mở trực tiếp tệp `public/index.html`, vì đăng nhập và tải ảnh cần máy chủ.

Sau đó bấm "Đăng nhập" → "Tạo tài khoản" để tạo tài khoản đầu tiên. Tài khoản có tên trùng `ADMIN_USERNAME` được xóa mọi ảnh.

## Cách hoạt động

- Đăng ký, đăng nhập, đăng xuất: mật khẩu được băm bằng bcrypt, phiên đăng nhập lưu trong cookie đã ký (HttpOnly, SameSite=Lax), sống 7 ngày.
- Tải ảnh: chỉ người đã đăng nhập; nhận JPG, PNG, WebP tối đa 5 MB. Máy chủ kiểm tra nội dung thật của tệp (không tin đuôi tên tệp) và đặt lại tên ngẫu nhiên.
- Mỗi tài khoản tối đa 30 ảnh. Người đăng tự xóa được ảnh của mình, quản trị viên xóa được mọi ảnh.
- Giới hạn tần suất: 20 lần đăng ký/đăng nhập mỗi 15 phút và 30 lần tải ảnh mỗi giờ cho mỗi địa chỉ IP.

## Cấu trúc

```
server.js          máy chủ Express (API và phục vụ tệp)
public/            giao diện: index.html, style.css, community.css, app.js, community.js
data/              db.json (tài khoản, thông tin ảnh) và khóa ký cookie, tự tạo khi chạy
uploads/           ảnh người dùng tải lên, tự tạo khi chạy
```

## Biến môi trường

| Biến | Ý nghĩa | Mặc định |
|---|---|---|
| `PORT` | Cổng chạy máy chủ | 3000 |
| `ADMIN_USERNAME` | Tên tài khoản quản trị | không có |
| `SESSION_SECRET` | Khóa ký cookie (nếu không đặt, tự sinh và lưu trong `data/`) | tự sinh |
| `COOKIE_SECURE` | Đặt `1` khi chạy qua HTTPS | tắt |
| `TRUST_PROXY` | Đặt `1` khi sau Nginx/Cloudflare để giới hạn tần suất đúng IP | tắt |
| `DATA_DIR`, `UPLOAD_DIR` | Nơi lưu dữ liệu và ảnh | `./data`, `./uploads` |

## Khi đưa lên mạng thật

- Chạy sau HTTPS (Nginx, Caddy, Cloudflare…) và đặt `COOKIE_SECURE=1`, `TRUST_PROXY=1`.
- Sao lưu định kỳ hai thư mục `data/` và `uploads/`.
- Dữ liệu lưu trong tệp JSON, phù hợp quy mô một trường. Nếu số người dùng lớn, nên chuyển sang SQLite hoặc PostgreSQL.

## Chưa có sẵn

- Quên mật khẩu và xác minh email.
- Kiểm duyệt ảnh trước khi hiển thị: ảnh hiện lên ngay sau khi đăng, quản trị viên xóa sau nếu cần.
- Nhà trường nên cân nhắc quy định về bảo vệ dữ liệu cá nhân và hình ảnh học sinh trước khi mở đăng ảnh công khai.
