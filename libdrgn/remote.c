#include "drgn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>

struct remote_ctx {
    int sock;
};

/* ---------------- GDB BACKEND -----------------------*/

static int connect_gdb_once(struct remote_ctx *ctx)
{
    if (ctx->sock > 0)
        return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    ctx->sock = sock;

    fprintf(stderr, "[GDB CONNECTED]\n");
    return 0;
}

static int send_gdb_packet(int sock, const char *payload)
{
    char packet[1024];
    unsigned char checksum = 0;

    for (const char *p = payload; *p; p++)
        checksum += *p;

    snprintf(packet, sizeof(packet), "$%s#%02x", payload, checksum);

    fprintf(stderr, "[SEND] %s\n", payload);

    if (send(sock, packet, strlen(packet), 0) < 0)
        return -1;

    return 0;
}

static int recv_gdb_response(int sock, char *buf, size_t max)
{
    char c;
    size_t i = 0;
    int started = 0;

    while (recv(sock, &c, 1, 0) == 1) {
        if (c == '$') {
            started = 1;
            continue;
        }

        if (started) {
            if (c == '#')
                break;

            if (i < max - 1)
                buf[i++] = c;
        }
    }

    buf[i] = '\0';

    recv(sock, &c, 1, 0);
    recv(sock, &c, 1, 0);

    send(sock, "+", 1, 0);

    return 0;
}

static void hex_to_bytes(const char *hex, void *out, size_t len)
{
    unsigned char *buf = out;

    for (size_t i = 0; i < len; i++)
        sscanf(hex + 2 * i, "%2hhx", &buf[i]);
}

static struct drgn_error *
remote_read_gdb_fn(void *buf, uint64_t address, size_t count,
                   uint64_t offset, void *arg, bool physical)
{
    struct remote_ctx *ctx = arg;

    if (connect_gdb_once(ctx) < 0)
        return drgn_error_create(DRGN_ERROR_OTHER, "GDB connect failed");

    fprintf(stderr,
        "[GDB READ] addr=0x%" PRIx64 " size=%zu\n",
        address, count);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "m%" PRIx64 ",%zx", address, count);

    if (send_gdb_packet(ctx->sock, cmd) < 0)
        return drgn_error_create(DRGN_ERROR_OTHER, "send failed");

    char response[4096];
    recv_gdb_response(ctx->sock, response, sizeof(response));

    if (strlen(response) < count * 2)
        return drgn_error_create(DRGN_ERROR_OTHER, "short GDB response");

    hex_to_bytes(response, buf, count);

    return NULL;
}

struct drgn_error *
drgn_program_enable_remote_gdb(struct drgn_program *prog)
{
    struct remote_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx)
        return drgn_error_create(DRGN_ERROR_OTHER, "malloc failed");

    ctx->sock = -1;

    fprintf(stderr, "[REMOTE INIT - GDB]\n");

    return drgn_program_add_memory_segment(
        prog,
        0x0,
        UINT64_MAX,
        remote_read_gdb_fn,
        ctx,
        false
    );
}

/* ---------------- QMP BACKEND -----------------------*/

static int connect_qmp_once(struct remote_ctx *ctx)
{
    if (ctx->sock > 0)
        return 0;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/qmp.sock");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    ctx->sock = sock;

    fprintf(stderr, "[QMP CONNECTED]\n");

    return 0;
}

static int qmp_handshake(struct remote_ctx *ctx)
{
    char buf[4096];

    /* read greeting */
    recv(ctx->sock, buf, sizeof(buf), 0);

    const char *cmd = "{\"execute\": \"qmp_capabilities\"}\n";
    send(ctx->sock, cmd, strlen(cmd), 0);

    recv(ctx->sock, buf, sizeof(buf), 0);

    fprintf(stderr, "[QMP INIT DONE]\n");
    return 0;
}

static int qmp_read_memory(struct remote_ctx *ctx,
                          uint64_t addr, size_t size,
                          void *out)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
        "{\"execute\": \"human-monitor-command\", "
        "\"arguments\": {\"command-line\": \"xp /%zubx 0x%lx\"}}\n",
        size, addr);

    send(ctx->sock, cmd, strlen(cmd), 0);

    char resp[8192];
    int n = recv(ctx->sock, resp, sizeof(resp) - 1, 0);
    if (n <= 0)
        return -1;

    resp[n] = '\0';

    fprintf(stderr, "[QMP RAW] %s\n", resp);

    if (!strstr(resp, "\"return\"")) {
        fprintf(stderr, "[QMP SKIP EVENT]\n");
        return -1;  
    }

    unsigned char *buf = out;
    size_t count = 0;

    char *p = resp;

    while ((p = strstr(p, "0x")) && count < size) {
        unsigned int byte;

        if (sscanf(p, "0x%x", &byte) == 1) {
            buf[count++] = byte;
        }

        p += 2;  
    }

    if (count < size) {
        fprintf(stderr, "[QMP ERROR] parsed %zu bytes, expected %zu\n", count, size);
        return -1;
    }

    return 0;
}


#define KERNEL_BASE 0xc000000000000000UL

static uint64_t virt_to_phys(struct remote_ctx *ctx, uint64_t vaddr)
{
    /* quick direct mapping (PPC64 linear mapping) */
    if (vaddr >= KERNEL_BASE)
        return vaddr - KERNEL_BASE;

    return vaddr;
}

static struct drgn_error *
remote_read_qmp_fn(void *buf, uint64_t address, size_t count,
                   uint64_t offset, void *arg, bool physical)
{
    struct remote_ctx *ctx = arg;

    if (connect_qmp_once(ctx) < 0)
        return drgn_error_create(DRGN_ERROR_OTHER, "QMP connect failed");

    static int initialized = 0;
    if (!initialized) {
        qmp_handshake(ctx);
        initialized = 1;
    }

    fprintf(stderr,
        "[QMP READ] addr=0x%" PRIx64 " size=%zu\n",
        address, count);

    uint64_t phys = virt_to_phys(ctx, address);

    fprintf(stderr,
        "[TRANSLATE] virt=0x%" PRIx64 " → phys=0x%" PRIx64 "\n",
        address, phys);

    if (qmp_read_memory(ctx, phys, count, buf) < 0)
        return drgn_error_create(DRGN_ERROR_OTHER, "QMP read failed");

    return NULL;
}

struct drgn_error *
drgn_program_enable_remote_qmp(struct drgn_program *prog)
{
    struct remote_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx)
        return drgn_error_create(DRGN_ERROR_OTHER, "malloc failed");

    ctx->sock = -1;

    fprintf(stderr, "[REMOTE INIT - QMP]\n");

    return drgn_program_add_memory_segment(
        prog,
        0x0,
        UINT64_MAX,
        remote_read_qmp_fn,
        ctx,
        false
    );
}