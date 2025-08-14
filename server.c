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

enum { GET = 1, POST };

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
    if (strcmp(method, "POST") == 0) { return POST; }
    return -1;
}

header* header_new(char *name, char *value) {
    header* head = malloc(sizeof(header));
    head->name = malloc(strlen(name) + 1);
    head->value = malloc(strlen(value) + 1);
    strcpy(head->name, name);
    strcpy(head->value, value);

    return head;
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

http_response* response_new(int status_code, char *phrase, char *body, header** headers, int header_count) {
    http_response *res = malloc(sizeof(http_response));
    res->version = "HTTP/1.0";
    res->status_code = status_code;
    
    res->phrase = malloc(strlen(phrase) + 1);
    strcpy(res->phrase, phrase);

    res->body = malloc(strlen(body) + 1);
    strcpy(res->body, body);

    header *head = header_new("Content-Type", "text/html");
    res->headers = malloc(sizeof(header*) * 2);
    res->headers[0] = head;
    
    size_t body_length = strlen(res->body);
    char length_str[32];  // Buffer for length string
    snprintf(length_str, sizeof(length_str), "%zu", body_length);
    header *head2 = header_new("Content-Length", length_str);
    res->headers[1] = head2;

    res->header_count = 2;
    
    if (headers) {
        res->headers = realloc(res->headers,
                               (res->header_count + header_count) * sizeof(header*));
        for (int i = res->header_count; i < header_count; i++) {
            res->headers[i] = headers[i];
        }
        res->header_count += header_count;
    }

    return res;
}

void response_del(http_response *res) {
    free(res->phrase);

    for (int i = 0; i < res->header_count; i++) {
        if (res->headers[i] != NULL) {
            free(res->headers[i]->name);
            free(res->headers[i]->value);
            free(res->headers[i]);
        }
    }

    free(res->headers);
    free(res->body);
    free(res);
}

http_response* handle_GET_request(http_request *req) {
    char *ubuf = malloc(strlen(req->uri) + 2);
    strcpy(ubuf + 1, req->uri);
    ubuf[0] = '.';
    
    FILE *file;
    file = fopen(ubuf, "r");

    if (file == NULL) {
        return response_new(NOT_FOUND,
                            "Not found",
                            "<html><body>Not found!</body></html>",
                            NULL, 0);
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *bbuf = malloc(length + 1);
    fread(bbuf, 1, length, file);
    bbuf[length] = '\0';
    
    http_response *res = response_new(OK, "OK", bbuf, NULL, 0);

    fclose(file);
    free(ubuf);
    free(bbuf);

    return res;
}


http_response* handle_request(http_request *req) {
    switch (req->method) {
        case GET:
            return handle_GET_request(req);
        case POST: break;
        default: break;
    }
    return NULL;
}

char* response_to_string(http_response *res) {
    int size = snprintf(NULL, 0, "%s %d %s\r\n\r\n", 
                       res->version, res->status_code, res->phrase);
    
    for (int i = 0; i < res->header_count; i++) {
        size += snprintf(NULL, 0, "%s: %s\r\n", 
                        res->headers[i]->name, res->headers[i]->value);
    }
    
    if (res->body) {
        size += strlen(res->body) + 1;
    }
    
    char *str = malloc(size + 1);
    int offset = 0;
    
    offset += sprintf(str + offset, "%s %d %s\r\n", 
                     res->version, res->status_code, res->phrase);
    
    for (int i = 0; i < res->header_count; i++) {
        offset += sprintf(str + offset, "%s: %s\r\n", 
                         res->headers[i]->name, res->headers[i]->value);
    }
    
    offset += sprintf(str + offset, "\r\n");
    if (res->body) {
        offset += sprintf(str + offset, "%s\n", res->body);
    }
    
    return str;
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

        if (n > 0) {
            http_request* req = request_new(); 
            request_parse(req, rbuf);
            printf("Method: %d\n", req->method);
            printf("Uri: %s\n", req->uri);
            printf("Version: %s\n", req->version);
            for (int i = 0; i < req->header_count; i++) {
                printf("%s:%s\n", req->headers[i]->name, req->headers[i]->value);
            }

            http_response *res = handle_request(req);
            char *wbuf = response_to_string(res);
            write(connfd, wbuf, strlen(wbuf));

            response_del(res);
            request_del(req);
        };
        close(connfd);
    }

    close(fd);
    return 0;
}
