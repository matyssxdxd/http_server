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
#define READ_BUFFER_SIZE 65536 

typedef enum {
    HEADER_CONTENT_LENGTH,
    HEADER_CONTENT_TYPE,
    HEADER_CONNECTION,
    HEADER_USER_AGENT,
    HEADER_ACCEPT,
    HEADER_AUTHORIZATION,
    HEADER_UNKNOWN
} header_type;

typedef enum { 
    GET = 1, 
    POST 
} method_type;

typedef enum { 
    OK = 200, 
    NOT_FOUND = 404,
    BAD_REQUEST = 400
} status_code;

typedef struct header {
    header_type type;
    char *name;
    char *value;
} header;

typedef struct http_request {
    method_type method;
    char *uri;
    char *version;
    header **headers;
    int header_count;
    char *body;
    int body_length;
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

method_type method_str_to_enum(char *method) {
    if (strcmp(method, "GET") == 0) { return GET; }
    if (strcmp(method, "POST") == 0) { return POST; }
    return -1;
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}


/*
 *  Header functions
 */

header* header_new(header_type type, char *name, char *value) {
    header* head = malloc(sizeof(header));
    head->type = type;
    head->name = malloc(strlen(name) + 1);
    head->value = malloc(strlen(value) + 1);
    strcpy(head->name, name);
    strcpy(head->value, value);

    return head;
}

void header_del(header* head) {
    free(head->name);
    free(head->value);
    free(head);
}

header_type header_get_type(const char *name) {
    static const struct {
        const char *name;
        header_type type;
    } header_map[] = {
        {"Content-Length", HEADER_CONTENT_LENGTH},
        {"Content-Type", HEADER_CONTENT_TYPE},
        {"Connection", HEADER_CONNECTION},
        {"User-Agent", HEADER_USER_AGENT},
        {"Accept", HEADER_ACCEPT},
        {"Authorization", HEADER_AUTHORIZATION}
    };

    for (size_t i = 0; i < sizeof(header_map) / sizeof(header_map[0]); i++) {
        if (strcmp(name, header_map[i].name) == 0) {
            return header_map[i].type;
        }
    }
    return HEADER_UNKNOWN;
}

char* header_get_value(http_request *req, const header_type type) {
    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i]->type == type) { return req->headers[i]->value; }
    }
    return NULL;
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
    req->body = NULL;
    req->body_length = 0;

    return req;
}

void request_add_header(http_request *req, header *head) {
    req->headers = realloc(req->headers,
                           (req->header_count + 1) * sizeof(header*));
    req->headers[req->header_count] = head;
    req->header_count++;
}

void request_del(http_request *req) {
    if (req == NULL) { return; }
    
    free(req->uri);
    free(req->version);

    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i] != NULL) {
            header_del(req->headers[i]);
        }
    }

    free(req->headers);
    free(req);
}

http_request* request_parse(char *rbuf) {
    http_request *req = request_new();
    char *tmp_ptr = rbuf;

    char *pos = strchr(tmp_ptr, ' ');
    if (!pos) {
        // All of these should be 400 Bad Request
        printf("Error: Cannot find the end of the HTTP method.");
        free(req);
        return NULL;
    }

    int method_len = pos - tmp_ptr;
    char *mbuf = malloc(method_len + 1);
    strncpy(mbuf, tmp_ptr, method_len);
    mbuf[method_len] = '\0';

    method_type method = method_str_to_enum(mbuf);
    req->method = method;
    free(mbuf);
    if (method < 0) { 
        printf("Error: Unsupported method.");
        free(req);
        return NULL; 
    } 

    tmp_ptr = pos;
    while (*tmp_ptr == ' ') { tmp_ptr++; }

    char *pos2 = strchr(tmp_ptr, ' ');
    if (!pos2) {
        printf("Error: Cannot find the end of the HTTP request URI.");
        free(req);
        return NULL;
    }

    int uri_len = pos2 - tmp_ptr;
    req->uri = malloc(uri_len + 1);
    strncpy(req->uri, tmp_ptr, uri_len);
    req->uri[uri_len] = '\0';

    tmp_ptr = pos2;
    while (*tmp_ptr == ' ') { tmp_ptr++; }

    char *crlf = strstr(tmp_ptr, "\r\n");
    if (!crlf) {
        printf("Error: Cannot find the end of the HTTP version.");
        free(req);
        return NULL;
    }

    int version_len = crlf - tmp_ptr;
    req->version = malloc(version_len + 1);
    strncpy(req->version, tmp_ptr, version_len);
    req->version[version_len] = '\0';

    int parsed_len = (crlf - rbuf) + 2;

    char *header_pos = rbuf + parsed_len;
    while (1) {
        char *line_end = strstr(header_pos, "\r\n");
        if (!line_end || line_end == header_pos) { break; }

        char *colon = strchr(header_pos, ':');
        if (!colon || colon > line_end) { continue; }

        int name_len = colon - header_pos;
        char *name = malloc(name_len + 1);
        strncpy(name, header_pos, name_len);
        name[name_len] = '\0';

        char *value_start = colon + 1;
        while (value_start < line_end && *value_start == ' ') {
            value_start++;
        }

        int value_len = line_end - value_start;
        char *value = malloc(value_len + 1);
        strncpy(value, value_start, value_len);
        value[value_len] = '\0';

        header *head = header_new(header_get_type(name), name, value);
        request_add_header(req, head);
        header_pos = line_end + 2;
    }

    char *body_pos = header_pos + 2;
    if (req->method == POST) {
        char *body_len = header_get_value(req, HEADER_CONTENT_LENGTH);
        if (body_len == NULL) {
            // Probably need to handle this somehow
            return req;
        } 
        req->body_length = strtol(body_len, NULL, 10);
        req->body = malloc(req->body_length + 1);
        strncpy(req->body, body_pos, req->body_length);
    }

    return req;
}

/*
 *   HTTP Response functions
 */

http_response* response_new(int status_code, char *phrase, char *body, header** headers, int header_count) {
    http_response *res = malloc(sizeof(http_response));
    res->version = "HTTP/1.0";
    res->status_code = status_code;
    res->header_count = 0;
    res->headers = NULL;

    res->phrase = malloc(strlen(phrase) + 1);
    strcpy(res->phrase, phrase);

    res->body = malloc(strlen(body) + 1);
    strcpy(res->body, body);

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
            header_del(res->headers[i]);
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

    return res;
}

http_response* handle_POST_request(http_request *req) {
    return NULL;
}


http_response* handle_request(http_request *req) {
    switch (req->method) {
        case GET:
            return handle_GET_request(req);
        case POST: 
            return handle_POST_request(req);
        default: 
            return response_new(BAD_REQUEST, "Bad request", "<html><body>Bad request!</body></html>", NULL, 0);
    }
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

int read_http_request(int sockfd, char *buf) {
    int total_read = 0;
    char *header_end = NULL;

    while (total_read < READ_BUFFER_SIZE - 1) {
        ssize_t n = read(sockfd, buf + total_read, READ_BUFFER_SIZE - total_read - 1);

        if (n <= 0) {
            if (n < 0) { die("read()"); }
            return -1;
        }

        total_read += n;
        buf[total_read] = '\0';

        header_end = strstr(buf, "\r\n\r\n");
        if (header_end) { return total_read; }

        if (total_read >= READ_BUFFER_SIZE - 1) { die("Too large header"); }
    }

    return total_read;
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

        char rbuf[READ_BUFFER_SIZE];
        int total_read = read_http_request(connfd, rbuf);

        http_request *req = request_parse(rbuf);
        http_response *res = handle_request(req);

        if (res) {
            char *wbuf = response_to_string(res);
            write(connfd, wbuf, strlen(wbuf));

            response_del(res);
            request_del(req);
        }

        close(connfd);
    }

    close(fd);
    return 0;
}
