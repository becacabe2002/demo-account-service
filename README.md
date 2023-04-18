# demo-account-service
Demo project for Authorization and News Category services

Local mysql server
* Tạo một cơ sở dữ liệu

```
create database AuthService
```
* Thêm người sử dụng 
**Sử dụng MySQL Workbench**
1. Truy cập local host connection với quyền root
2. Server > Users and Privileges
3. Thêm user: username - password
4. Thay đổi cấu hình trong file application.yaml tương ứng với local host

### Chạy chuơng trình
* `cd path/to/clonedProject`
* `mvn dependencies:resolve`
* `mvn spring-boot:run`
* Mở postman, import các lệnh trong file .json để test.
