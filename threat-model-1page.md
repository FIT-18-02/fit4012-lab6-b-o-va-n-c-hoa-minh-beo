# Threat Model - Lab 6 AES-CBC Socket

## Thông tin nhóm

- Thành viên 1: Dong Do Bao
- Thành viên 2: Dao Van Minh 

## Assets

Các tài sản cần bảo vệ trong hệ thống:

- Plaintext của người dùng trước khi mã hóa
- AES key dùng để mã hóa và giải mã
- IV (Initialization Vector)
- Ciphertext được gửi qua socket
- File đầu vào (sample_input.txt)
- File đầu ra (sample_output.txt)
- Log của sender và receiver
- Địa chỉ IP và port sử dụng trong quá trình demo

## Attacker model

Kẻ tấn công có thể:

- Nghe lén mạng LAN trong cùng môi trường mạng
- Bắt gói tin trên KEY_PORT
- Bắt gói tin trên DATA_PORT
- Sửa ciphertext trong lúc truyền
- Replay lại packet cũ
- Đọc log nếu file log bị lộ
- Giả mạo Sender để gửi dữ liệu tới Receiver
- Gửi packet lỗi để làm Receiver bị treo hoặc lỗi

## Threats

### 1. Key disclosure

AES key và IV được gửi plaintext qua key channel nên có thể bị lộ nếu attacker bắt được packet.

### 2. Tampering

Ciphertext có thể bị sửa trên đường truyền khiến dữ liệu giải mã sai hoặc gây lỗi padding.

### 3. Replay attack

Attacker có thể gửi lại packet cũ nhiều lần vì hệ thống chưa có nonce hoặc timestamp để kiểm tra tính mới của dữ liệu.

### 4. Log leakage

Nếu hệ thống ghi key hoặc IV vào log thật thì attacker có thể đọc log và giải mã dữ liệu.

### 5. No authentication

Receiver chưa xác thực Sender nên attacker có thể giả mạo Sender để gửi dữ liệu giả.

### 6. Denial of Service

Attacker có thể gửi packet lỗi hoặc chiếm port làm Receiver không hoạt động đúng.

## Mitigations

### 1. Không gửi key plaintext

Trong hệ thống thực tế cần dùng cơ chế trao đổi khóa an toàn thay vì gửi AES key trực tiếp qua socket.

### 2. Dùng TLS

Sử dụng TLS để mã hóa kết nối và bảo vệ dữ liệu khi truyền qua mạng.

### 3. Dùng AES-GCM

AES-GCM hỗ trợ vừa mã hóa vừa xác thực dữ liệu để phát hiện tampering.

### 4. Không ghi key vào log

Trong môi trường thực tế không nên ghi key hoặc IV thật vào file log.

### 5. Thêm nonce hoặc timestamp

Giúp giảm nguy cơ replay attack bằng cách kiểm tra packet cũ.

### 6. Xác thực Sender

Receiver cần kiểm tra danh tính Sender trước khi chấp nhận dữ liệu.

### 7. Kiểm tra dữ liệu đầu vào

Kiểm tra header, kích thước ciphertext và timeout để tránh lỗi hoặc DoS.

## Residual risks

Hệ thống hiện tại chỉ phục vụ mục đích học tập và demo trong môi trường nội bộ. Dù đã tách key channel và data channel, hệ thống vẫn chưa an toàn để triển khai thực tế vì chưa có TLS, chưa xác thực Sender và chưa chống replay đầy đủ.