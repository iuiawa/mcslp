#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctime>
#include <sstream>
#include <iomanip>

// ================= 纯 C++ 实现的 SHA-512 =================
typedef unsigned long long uint64;
const uint64 MAX_SHA512_LEN = 128;

struct SHA512_CTX {
    uint64 h[8];
    unsigned char buffer[128];
    uint64 totalLen;
};

const uint64 sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

void sha512_transform(SHA512_CTX* ctx, const unsigned char* data) {
    uint64 W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint64)data[i*8] << 56) | ((uint64)data[i*8+1] << 48) | ((uint64)data[i*8+2] << 40) | ((uint64)data[i*8+3] << 32) |
               ((uint64)data[i*8+4] << 24) | ((uint64)data[i*8+5] << 16) | ((uint64)data[i*8+6] << 8) | ((uint64)data[i*8+7]);
    }
    for (int i = 16; i < 80; i++) {
        W[i] = ROTR64(W[i-2], 19) ^ ROTR64(W[i-2], 61) ^ (W[i-2] >> 6) + W[i-15] + ROTR64(W[i-15], 1) ^ ROTR64(W[i-15], 8) ^ (W[i-15] >> 7) + W[i-16];
    }
    uint64 a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4],f=ctx->h[5],g=ctx->h[6],h=ctx->h[7];
    for (int i = 0; i < 80; i++) {
        uint64 t1 = h + sha512_k[i] + (ROTR64(e,14) ^ ROTR64(e,18) ^ ROTR64(e,41)) + ((e&f)^((~e)&g)) + W[i];
        uint64 t2 = (ROTR64(a,28) ^ ROTR64(a,34) ^ ROTR64(a,39)) + ((a&b)^(a&c)^(b&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d; ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

std::string sha512(const std::string& input) {
    SHA512_CTX ctx;
    ctx.h[0]=0x6a09e667f3bcc908ULL; ctx.h[1]=0xbb67ae8584caa73bULL; ctx.h[2]=0x3c6ef372fe94f82bULL; ctx.h[3]=0xa54ff53a5f1d36f1ULL;
    ctx.h[4]=0x510e527fade682d1ULL; ctx.h[5]=0x9b05688c2b3e6c1fULL; ctx.h[6]=0x1f83d9abfb41bd6bULL; ctx.h[7]=0x5be0cd19137e2179ULL;
    ctx.totalLen = 0;
    
    unsigned char buffer[128];
    size_t i = 0;
    while (i < input.size()) {
        buffer[ctx.totalLen % 128] = input[i];
        ctx.totalLen++;
        if (ctx.totalLen % 128 == 0) sha512_transform(&ctx, buffer);
        i++;
    }
    
    buffer[ctx.totalLen % 128] = 0x80;
    if ((ctx.totalLen % 128) >= 112) {
        for(int j = (ctx.totalLen % 128)+1; j < 128; j++) buffer[j] = 0;
        sha512_transform(&ctx, buffer);
        memset(buffer, 0, 112);
    } else {
        for(int j = (ctx.totalLen % 128)+1; j < 112; j++) buffer[j] = 0;
    }
    
    uint64 bitLen = ctx.totalLen * 8;
    for (int j = 0; j < 8; j++) buffer[119 - j] = (bitLen >> (j * 8)) & 0xFF;
    buffer[120] = 0; buffer[121] = 0; buffer[122] = 0; buffer[123] = 0; buffer[124] = 0; buffer[125] = 0; buffer[126] = 0; buffer[127] = 0;
    sha512_transform(&ctx, buffer);
    
    std::stringstream ss;
    for (int j = 0; j < 8; j++) {
        ss << std::hex << std::setfill('0') << std::setw(16) << ctx.h[j];
    }
    return ss.str();
}
// ================= SHA-512 结束 =================

// 【重要】在此处修改你的 Token 密钥，必须和前端 URL 里的 token 参数一致
const std::string SECRET_TOKEN = "my_secret_random_string_123";

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    bind(server_fd, (sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);
    std::cout << "C++ 鉴权代理已启动，监听 8080..." << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        char http_buf[2048] = {0};
        recv(client_fd, http_buf, sizeof(http_buf), 0);
        std::string request(http_buf);
        
        // 提取 URL: GET /?svr=...&ts=...&hash=... HTTP/1.1
        int url_start = request.find("GET /") + 5;
        int url_end = request.find(" HTTP");
        if (url_start < 0 || url_end < 0) { close(client_fd); continue; }
        std::string query = request.substr(url_start, url_end - url_start);

        // 简单解析参数
        std::string svr = "", ts = "", hash = "";
        auto parseParam = [&](const std::string& key) {
            size_t pos = query.find(key + "=");
            if (pos != std::string::npos) {
                size_t start = pos + key.length() + 1;
                size_t end = query.find("&", start);
                if (end == std::string::npos) end = query.length();
                return query.substr(start, end - start);
            }
            return std::string("");
        };
        svr = parseParam("svr");
        ts = parseParam("ts");
        hash = parseParam("hash");

        // 1. 检查时间戳 (±60秒内有效)
        long long current_ts = (long long)time(nullptr);
        if (ts.empty() || std::abs(current_ts - std::stoll(ts)) > 60) {
            std::string resp = "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"error\":\"时间戳过期或无效\"}";
            send(client_fd, resp.c_str(), resp.length(), 0);
            close(client_fd);
            continue;
        }

        // 2. 验证 SHA-512 密钥
        std::string expected_hash = sha512(SECRET_TOKEN + ts);
        if (hash != expected_hash) {
            std::string resp = "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"error\":\"密钥鉴权失败\"}";
            send(client_fd, resp.c_str(), resp.length(), 0);
            close(client_fd);
            continue;
        }

        // 3. 鉴权通过，解析 MC 服务器地址和端口
        std::string mc_host = svr;
        int mc_port = 25565;
        size_t colon = svr.find(':');
        if (colon != std::string::npos) {
            mc_host = svr.substr(0, colon);
            mc_port = std::stoi(svr.substr(colon + 1));
        }

        int mc_fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in mc_addr;
        mc_addr.sin_family = AF_INET;
        mc_addr.sin_port = htons(mc_port);
        inet_pton(AF_INET, mc_host.c_str(), &mc_addr.sin_addr);

        if (connect(mc_fd, (sockaddr*)&mc_addr, sizeof(mc_addr)) < 0) {
            std::string resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n{\"error\":\"无法连接MC服务器\"}";
            send(client_fd, resp.c_str(), resp.length(), 0);
            close(mc_fd); close(client_fd); continue;
        }

        // 4. 动态构造并发送 SLP 握手包
        std::vector<char> handshake;
        handshake.push_back(0x00); // Packet ID
        handshake.push_back(0xFF); handshake.push_back(0xFF); handshake.push_back(0xFF); handshake.push_back(0xFF); handshake.push_back(0x0F); // Protocol -1
        handshake.push_back((char)mc_host.length()); // String Length (假设IP不超127)
        for(char c : mc_host) handshake.push_back(c); // Host String
        handshake.push_back((mc_port >> 8) & 0xFF); handshake.push_back(mc_port & 0xFF); // Port
        handshake.push_back(0x01); // Next State

        std::vector<char> final_packet;
        final_packet.push_back((char)handshake.size());
        final_packet.insert(final_packet.end(), handshake.begin(), handshake.end());
        
        send(mc_fd, final_packet.data(), final_packet.size(), 0);
        send(mc_fd, "\x01\x00", 2, 0); // Status Request

        // 5. 读取 MC 返回数据
        char mc_buf[4096] = {0};
        std::string mc_data = "";
        int bytes_read;
        while ((bytes_read = recv(mc_fd, mc_buf, sizeof(mc_buf) - 1, 0)) > 0) {
            mc_buf[bytes_read] = '\0';
            mc_data += mc_buf;
            if (mc_data.find('}') != std::string::npos) break;
        }
        close(mc_fd);

        int start = mc_data.find('{');
        int end = mc_data.rfind('}');
        std::string json_str = "{}";
        if (start != -1 && end != -1 && end > start) json_str = mc_data.substr(start, end - start + 1);

        std::string http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n" + json_str;
        send(client_fd, http_resp.c_str(), http_resp.length(), 0);
        close(client_fd);
    }
    return 0;
}
