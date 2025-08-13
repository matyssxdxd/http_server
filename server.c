#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>

#define PORT 1337

typedef struct header {
    char *name;
    char *value;
} header;

typedef struct http_request {
    char *method;
    char *request_uri;
    char *version;
    header **headers;
    int header_count;
    int len;
} http_request;

int len(char *rbuf, char *str) {
    char *pos = strstr(rbuf, str);
    if (pos != NULL) {
        return pos - rbuf;
    }
    return -1;
}

void parse_first_line(http_request *req, char *rbuf) {
    int length = len(rbuf, " ");
    if (length <= 0) { printf("Error"); }
    req->method = malloc(length + 1);
    strncpy(req->method, rbuf, length);
    req->method[length] = '\0';
    req->len += length + 1;

    length = len(rbuf + req->len, " ");
    req->request_uri = malloc(length + 1);
    strncpy(req->request_uri, rbuf + req->len, length);
    req->request_uri[length] = '\0';
    req->len += length + 1;

    length = len(rbuf + req->len, "\r\n");
    req->version = malloc(length + 1);
    strncpy(req->version, rbuf + req->len, length);
    req->version[length] = '\0';
    req->len += length + 2;
}

void parse_headers(http_request *req, char *rbuf) {
    while (1) {
        char *pos = strstr(rbuf + req->len, "\r\n");
        if (pos == NULL) {
            break;
        }

        int length = pos - rbuf - req->len;
        if (length == 0) { req->len += 2; break; }

        char *buf = malloc(length + 1);
        strncpy(buf, rbuf + req->len, length);
        buf[length] = '\0';
        pos = strstr(buf, ":");
        if (pos != NULL) {
            header *head = malloc(sizeof(header));
            int name_len = pos - buf;
            char *value_pos = pos + 2;
            int value_len = (buf + length) - value_pos;

            head->name = malloc(name_len + 1); 
            head->value = malloc(value_len + 1);
            strncpy(head->name, buf, name_len);
            strncpy(head->value, value_pos, value_len); 
            head->name[name_len] = '\0';
            head->value[value_len] = '\0';

            req->headers = realloc(req->headers,
                                   (req->header_count + 1) * sizeof(header*));
            req->headers[req->header_count] = head;
            req->header_count++;
        }
        free(buf);
        req->len += length + 2;
    }
}

http_request* parse_request(char *rbuf) {
    http_request *request = malloc(sizeof(http_request));
    request->len = 0;
    request->header_count = 0;
    request->headers = NULL;

    parse_first_line(request, rbuf);
    parse_headers(request, rbuf);

    return request;
}

void free_http_request(http_request *req) {
    if (req == NULL) { return; }
    
    free(req->method);
    free(req->request_uri);
    free(req->version);

    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i] != NULL) {
            free(req->headers[i]->name);
            free(req->headers[i]->value);
            free(req->headers[i]);
        }
    }

    free(req->headers);
    free(req);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(0);
    int rv = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv) { die("bind()"); }

    rv = listen(fd, SOMAXCONN);
    if (rv) { die("listen()"); }
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int connfd = accept(fd, (struct sockaddr *)&client_addr, &addrlen);
        if (connfd < 0) {
            continue;
        }

        char rbuf[65536];
        ssize_t n = read(connfd, rbuf, sizeof(rbuf)- 1);
        if (n < 0) {
            die("read()");
            break;
        }
        
        #if 0
        for (int i = 0; rbuf[i] != '\0'; i++) {
            switch (rbuf[i]) {
                case '\n':
                    printf("\\n");
                    break;
                case '\r':
                    printf("\\r");
                    break;
                case '\t':
                    printf("\\t");
                    break;
                case '\\':
                    printf("\\\\");
                    break;
                default:
                    printf("%c", rbuf[i]);
            }
        }
        printf("\n");
        #endif

        #if 1
        http_request* req = parse_request(rbuf);
        printf("%s\n", req->method);
        printf("%s\n", req->request_uri);
        printf("%s\n", req->version);
        for (int i = 0; i < req->header_count; i++) {
            printf("%s:%s\n", req->headers[i]->name, req->headers[i]->value);
        }

        if (strcmp(req->request_uri, "/") == 0) {
            char wbuf[] = "HTTP/1.1 200 OK\r\n"
                "Date: Mon, 27 Jul 2002 11:38:44 GMT\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 46\r\n"
                "\r\n"
                "<html><body><h1>Hello, World!</h1></body></html>";
            write(connfd, wbuf, strlen(wbuf));
        }
        #endif
        
        free_http_request(req);
        close(connfd);
    }

    close(fd);
    return 0;
}
