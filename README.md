# byr_backend_project
## FuseTP

### 简介
本项目实现了一个基于 FUSE 的远程文件系统客户端。通过 SSH 和 SFTP 协议与远程服务器进行通信，用户可以通过本地挂载点浏览远程服务器上的文件系统，支持创建、读取、写入文件等操作。同时，项目实现了审计日志记录功能，记录所有用户的文件操作行为，并在远程服务器上存储日志。该系统还通过设计缓存、延迟写回、零拷贝、批量操作等优化选项，减少内核态与用户态之间的拷贝次数，提高了文件操作的效率。

### 功能
- 基于 FUSE 实现远程文件系统客户端
- 支持 SSH/SFTP 连接，进行文件操作（创建、读取、写入等）
- 支持审计日志功能，将操作记录存储到远程服务器
- 启用了 `writeback_cache` 和 `async_read` 优化策略，提升文件操作性能

### 环境要求
- Linux 操作系统
- 安装以下依赖包：
  - `fuse3`
  - `libssh`
  - `pkg-config`
  - `gcc`

### 编译
要编译该 FUSE 客户端，请执行以下命令：

```bash
gcc -o fuse_client fuse_client.c `pkg-config fuse3 libssh --cflags --libs` -D_FILE_OFFSET_BITS=64
