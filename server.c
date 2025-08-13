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

enum { GET = 1, HEAD, POST, PUT, DELETE, CONNECT, TRACE, PATCH, OPTIONS };

enum { OK = 200, NOT_FOUND = 404 };

typedef struct header {
    char *name;
    char *value;
} header;

typedef struct http_request {
    int method;
    char *uri;
    char *version;
    header **headers;
    int header_count;
    int len;
} http_request;

typedef struct http_response {
    char *version;
    int status_code;
    char *phrase;
    header **headers;
    int header_count;
    char *body;
} http_response;

/*
 *  Helpers
 */

int len(char *rbuf, char *str) {
    char *pos = strstr(rbuf, str);
    if (pos != NULL) {
        return pos - rbuf;
    }
    return -1;
}

int method_str_to_enum(char *method) {
    if (strcmp(method, "GET") == 0) { return GET; }
    if (strcmp(method, "HEAD") == 0) { return HEAD; }
    if (strcmp(method, "OPTIONS") == 0) { return OPTIONS; }
    if (strcmp(method, "TRACE") == 0) { return TRACE; }
    if (strcmp(method, "PUT") == 0) { return PUT; }
    if (strcmp(method, "DELETE") == 0) { return DELETE; }
    if (strcmp(method, "POST") == 0) { return POST; }
    if (strcmp(method, "PATCH") == 0) { return PATCH; }
    if (strcmp(method, "CONNECT") == 0) { return CONNECT; }
    return -1;
}

/*
 *   HTTP Request functions
 */

http_request* request_new() {
    http_request *req = malloc(sizeof(http_request));
    req->method = -1;
    req->uri = NULL;
    req->version = NULL;
    req->headers = NULL;
    req->header_count = 0;
    req->len = 0;

    return req;
}

void request_del(http_request *req) {
    if (req == NULL) { return; }
    
    free(req->uri);
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

void request_first_line(http_request *req, char *rbuf) {
    int length = len(rbuf, " ");
    if (length <= 0) { printf("Error"); }
    char *mbuf = malloc(length + 1);
    strncpy(mbuf, rbuf, length);
    mbuf[length] = '\0';
    int method = method_str_to_enum(mbuf);
    if (method <= 0) { return; } // return an error response 400
    req->method = method;
    req->len += length + 1;
    free(mbuf);

    length = len(rbuf + req->len, " ");
    req->uri = malloc(length + 1);
    strncpy(req->uri, rbuf + req->len, length);
    req->uri[length] = '\0';
    req->len += length + 1;

    length = len(rbuf + req->len, "\r\n");
    req->version = malloc(length + 1);
    strncpy(req->version, rbuf + req->len, length);
    req->version[length] = '\0';
    req->len += length + 2;
}

void request_headers(http_request *req, char *rbuf) {
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

void request_parse(http_request *req, char *rbuf) {
    request_first_line(req, rbuf);
    request_headers(req, rbuf);
}

/*
 *   HTTP Response functions
 */

http_response* response_new() {
    http_response *res = malloc(sizeof(http_response));
    res->version = NULL;
    res->status_code = -1;
    res->phrase = NULL;
    res->body = NULL;
    res->headers = NULL;

    return res;
}

void response_del(http_response *res) {
    free(res->version);
    free(res->phrase);
    
    for (int i = 0; i < res->header_count; i++) {
        if (res->headers[i] != NULL) {
            free(res->headers[i]->name);
            free(res->headers[i]->value);
            free(res->headers[i]);
        }
    }

    free(res->body);
    free(res);
}

http_response* handle_request(http_request *req) {
    switch (req->method) {
        case GET:
            {
                FILE *file;
                char *uri = malloc(strlen(req->uri) + 2);
                strcpy(uri + 1, req->uri);
                uri[0] = '.';
                file = fopen(uri, "r");
                if (file == NULL) { return NULL; }
                fseek(file, 0, SEEK_END);
                long length = ftell(file);
                fseek(file, 0, SEEK_SET);
                char *body = malloc(length + 1);
                if (body) {
                    fread(body, 1, length, file);
                    body[length] = '\0';
                }
                fclose(file);
                http_response *res = malloc(sizeof(http_response));
                res->status_code = OK;
                res->phrase = "OK";
                res->version = "HTTP/1.1";
                res->body = malloc(strlen(body) + 1);
                strcpy(res->body, body);
                return res;
            }
            break;
            // Look at the requested URL
            // If it exists, send a response and the file as a body
            // Else send a 404
        case POST: break;
        default: break;
    }
    return NULL;
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
        
        rbuf[n] = '\0';
        
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

        if (n > 0) {
            http_request* req = request_new(); 
            request_parse(req, rbuf);
            printf("Method: %d\n", req->method);
            printf("Uri: %s\n", req->uri);
            printf("Version: %s\n", req->version);
            for (int i = 0; i < req->header_count; i++) {
                printf("%s:%s\n", req->headers[i]->name, req->headers[i]->value);
            }

            // handle_request(req);

            // if (strcmp(req->uri, "/") == 0) {
            //     char wbuf[] = "HTTP/1.1 200 OK\r\n"
            //         "Date: Mon, 27 Jul 2002 11:38:44 GMT\r\n"
            //         "Content-Type: text/html\r\n"
            //         "Content-Length: 46\r\n"
            //         "\r\n"
            //         "<html><body><h1>Hello, World!</h1></body></html>";
            //     write(connfd, wbuf, strlen(wbuf));
            // }

            request_del(req);
        };
        close(connfd);
    }

    close(fd);
    return 0;
}
