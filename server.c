#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include "server.h"

#define READ_BUFFER_SIZE 65536 

static void die(const char* msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

method_t method_str_to_enum(char* method) {
    if (strcmp(method, "GET") == 0) { return HTTP_GET; }
    if (strcmp(method, "POST") == 0) { return HTTP_POST; }
    return -1;
}

/*
 *  Header functions
 */

http_header* new_header(header_t type, char* name, char* value) {
    http_header* head = malloc(sizeof(http_header));
    head->type = type;
    head->name = malloc(strlen(name) + 1);
    head->value = malloc(strlen(value) + 1);
    strcpy(head->name, name);
    strcpy(head->value, value);

    return head;
}

void del_header(http_header* head) {
    free(head->name);
    free(head->value);
    free(head);
}

header_t get_header_type(const char* name) {
    static const struct {
        const char* name;
        header_t type;
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

char* get_header_value(http_request* req, const header_t type) {
    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i]->type == type) { return req->headers[i]->value; }
    }
    return NULL;
}

/*
 *   HTTP Request functions
 */

http_request* new_request() {
    http_request* req = malloc(sizeof(http_request));
    req->method = -1;
    req->uri = NULL;
    req->version = NULL;
    req->headers = NULL;
    req->header_count = 0;
    req->body = NULL;
    req->body_length = 0;

    return req;
}

void add_request_header(http_request* req, http_header* head) {
    req->headers = realloc(req->headers,
                           (req->header_count + 1) * sizeof(http_header*));
    req->headers[req->header_count] = head;
    req->header_count++;
}

void del_request(http_request* req) {
    if (req == NULL) { return; }
    
    free(req->uri);
    free(req->version);

    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i] != NULL) {
            del_header(req->headers[i]);
        }
    }

    free(req->headers);
    free(req);
}

http_request* parse_request(char* rbuf) {
    http_request* req = new_request();
    char* tmp_ptr = rbuf;

    char* pos = strchr(tmp_ptr, ' ');
    if (!pos) {
        printf("Error: Cannot find the end of the HTTP method.");
        free(req);
        return NULL;
    }

    int method_len = pos - tmp_ptr;
    char* mbuf = malloc(method_len + 1);
    strncpy(mbuf, tmp_ptr, method_len);
    mbuf[method_len] = '\0';

    method_t method = method_str_to_enum(mbuf);
    req->method = method;
    free(mbuf);
    if (method < 0) { 
        printf("Error: Unsupported method.");
        free(req);
        return NULL; 
    } 

    tmp_ptr = pos;
    while (*tmp_ptr == ' ') { tmp_ptr++; }

    char* pos2 = strchr(tmp_ptr, ' ');
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

    char* crlf = strstr(tmp_ptr, "\r\n");
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

    char* header_pos = rbuf + parsed_len;
    while (1) {
        char* line_end = strstr(header_pos, "\r\n");
        if (!line_end || line_end == header_pos) { break; }

        char* colon = strchr(header_pos, ':');
        if (!colon || colon > line_end) { continue; }

        int name_len = colon - header_pos;
        char* name = malloc(name_len + 1);
        strncpy(name, header_pos, name_len);
        name[name_len] = '\0';

        char* value_start = colon + 1;
        while (value_start < line_end && *value_start == ' ') {
            value_start++;
        }

        int value_len = line_end - value_start;
        char* value = malloc(value_len + 1);
        strncpy(value, value_start, value_len);
        value[value_len] = '\0';

        http_header *head = new_header(get_header_type(name), name, value);
        add_request_header(req, head);
        header_pos = line_end + 2;
    }

    char* body_pos = header_pos + 2;
    if (req->method == HTTP_POST) {
        char* body_len = get_header_value(req, HEADER_CONTENT_LENGTH);
        if (body_len == NULL) {
            // Probably need to handle this somehow
            return req;
        } 
        req->body_length = strtol(body_len, NULL, 10);
        req->body = malloc(req->body_length + 1);
        strncpy(req->body, body_pos, req->body_length);
        req->body[req->body_length] = '\0';
    }

    return req;
}

/*
 *   HTTP Response functions
 */

http_response* new_response() {
    http_response* res = malloc(sizeof(http_response));
    res->version = NULL;
    res->status_code = UNKNOWN;
    res->headers = NULL;
    res->header_count = 0;
    res->phrase = NULL;
    res->body = NULL;

    return res;
}

void add_default_headers(http_response* res) {
    size_t body_len = strlen(res->body);
    char body_len_str[32];
    snprintf(body_len_str, sizeof(body_len_str), "%zu", body_len);
    http_header* content_len = new_header(HEADER_CONTENT_LENGTH, "Content-Length", body_len_str);
    http_header* content_type = new_header(HEADER_CONTENT_TYPE, "Content-Type", "text/html");

    res->headers = malloc(sizeof(http_header*) * 2);
    res->headers[res->header_count++] = content_len;
    res->headers[res->header_count++] = content_type;
}

http_response* response_bad_request() {
    http_response* res = new_response();
    
    res->version = malloc(strlen("HTTP/1.0") + 1);
    strcpy(res->version, "HTTP/1.0");
    
    res->status_code = BAD_REQUEST;

    res->phrase = malloc(strlen("Bad Request!") + 1);
    strcpy(res->phrase, "Bad Request!");

    res->body = malloc(strlen("<html><body><h1>Bad Request!</h1></body></html>") + 1);
    strcpy(res->body, "<html><body><h1>Bad Request!</h1></body></html>");

    add_default_headers(res);

    return res;
}

http_response* response_not_found() {
    http_response* res = new_response();

    res->version = malloc(strlen("HTTP/1.0") + 1);
    strcpy(res->version, "HTTP/1.0");

    res->status_code = NOT_FOUND;

    res->phrase = malloc(strlen("Not Found!") + 1);
    strcpy(res->phrase, "Not Found!");

    res->body = malloc(strlen("<html><body><h1>Bad Request!</h1></body></html>") + 1);
    strcpy(res->body, "<html><body><h1>Not Found!</h1></body></html>");

    add_default_headers(res);

    return res;
}

http_response* response_ok(char* body) {
    http_response* res = new_response();

    res->version = malloc(strlen("HTTP/1.0") + 1);
    strcpy(res->version, "HTTP/1.0");

    res->status_code = OK;

    res->phrase = malloc(strlen("OK!") + 1);
    strcpy(res->phrase, "OK!");

    res->body = malloc(strlen(body) + 1);
    strcpy(res->body, body);

    add_default_headers(res);

    return res;
}

void del_response(http_response* res) {
    free(res->version);
    free(res->phrase);

    for (int i = 0; i < res->header_count; i++) {
        if (res->headers[i] != NULL) {
            del_header(res->headers[i]);
        }
    }
    
    free(res->headers);
    free(res->body);
    free(res);
}

http_response* handle_GET_request(http_server* server, http_request* req) {
    int route_idx = find_route(server, req->uri, req->method);
    if (route_idx == -1) { return response_not_found(); }
    
    FILE* file;
    file = fopen(server->routes[route_idx]->file_path, "r");

    if (file == NULL) {
        return response_not_found();
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *bbuf = malloc(length + 1);
    fread(bbuf, 1, length, file);
    bbuf[length] = '\0';
    
    http_response* res = response_ok(bbuf);

    fclose(file);

    return res;
}

http_response* handle_POST_request(http_request* req) {
    
    char* tmp_ptr = req->body;
    pairs* key_vals = malloc(sizeof(pairs));
    key_vals->key = NULL;
    key_vals->value = NULL;
    key_vals->len = 0;
    while (1) {
        char* amp_pos = strchr(tmp_ptr, '&');
        char* eq_pos = strchr(tmp_ptr, '='); 
        int key_len = eq_pos - tmp_ptr;
        int val_len;
        if (amp_pos) {
            val_len = amp_pos - eq_pos - 1;
        } else {
            val_len = req->body_length - key_len; 
        }
        char* key = malloc(key_len + 1);
        char* val = malloc(val_len + 1);
        strncpy(key, tmp_ptr, key_len);
        strncpy(val, eq_pos + 1, val_len);
        key[key_len] = '\0';
        val[val_len] = '\0';
        key_vals->key = realloc(key_vals->key,
                                (key_vals->len + 1) * sizeof(char*));
        key_vals->value = realloc(key_vals->value,
                                (key_vals->len + 1) * sizeof(char*));
        key_vals->key[key_vals->len] = key;
        key_vals->value[key_vals->len] = val;
        key_vals->len++;
        if (amp_pos) {
            tmp_ptr = amp_pos + 1;
        } else {
            break;
        }
    }
    // Extract key:value pairs from body
    // Do something with it?
    // Needs cleanup, no idea what to do with them
    for (int i = 0; i < key_vals->len; i++) {
        printf("%s: %s\n", key_vals->key[i], key_vals->value[i]);
    }

    for (int i = 0; i < key_vals->len; i++) {
        free(key_vals->key[i]);
        free(key_vals->value[i]);
    }
    
    free(key_vals->key);
    free(key_vals->value);
    free(key_vals);

    return response_ok("<html><body><h1>Success!</h1></html></body>");
}


http_response* handle_request(http_server* server, http_request* req) {
    switch (req->method) {
        case HTTP_GET:
            return handle_GET_request(server, req);
        case HTTP_POST: 
            return handle_POST_request(req);
        default: 
            return response_bad_request(); 
    }
}

char* response_to_string(http_response* res) {
    int size = snprintf(NULL, 0, "%s %d %s\r\n\r\n", 
                       res->version, res->status_code, res->phrase);
    
    for (int i = 0; i < res->header_count; i++) {
        size += snprintf(NULL, 0, "%s: %s\r\n", 
                        res->headers[i]->name, res->headers[i]->value);
    }
    
    if (res->body) {
        size += strlen(res->body) + 1;
    }
    
    char* str = malloc(size + 1);
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

int read_http_request(int sockfd, char* buf) {
    int total_read = 0;
    char* header_end = NULL;

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

http_server* new_server(char* addr, int port) {
    http_server* server = malloc(sizeof(http_server)); 
    server->routes = NULL;
    server->route_count = 0;

    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) { die("Error creating socket"); }

    int val = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    memset(&server->addr, 0, sizeof(server->addr));
    server->addr.sin_family = AF_INET;
    server->addr.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &(server->addr.sin_addr)) == 0) { die("Invalid IPv4 address"); };

    if (bind(server->fd, (const struct sockaddr *)&server->addr, sizeof(server->addr))) {
        die("Error binding socket");
    }

    if (listen(server->fd, SOMAXCONN)) { die("Error listening"); }

    return server;
}

void launch_server(http_server* server) {
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int connfd = accept(server->fd, (struct sockaddr *)&client_addr, &addrlen);
        if (connfd < 0) {
            continue;
        }

        char rbuf[READ_BUFFER_SIZE];
        read_http_request(connfd, rbuf);

        http_request* req = parse_request(rbuf);
        if (strcmp(req->uri, "/favicon.ico") == 0) { write(connfd, "yes", 3); continue; }
        http_response *res = handle_request(server, req);

        char *wbuf = response_to_string(res);
        write(connfd, wbuf, strlen(wbuf));

        del_response(res);
        del_request(req);

        close(connfd);
    }
}

void close_server(http_server* server) {
    close(server->fd);
    
    if (server->routes) {
        for (int i = 0; i < server->route_count; i++) {
            del_route(server->routes[i]);
        }
    }
    free(server->routes);
    free(server);
}

void new_route(http_server* server, char* uri, char* file_path, method_t method) {
    server->routes = realloc(server->routes,
                             (server->route_count + 1) * sizeof(route*));

    route* new_route = malloc(sizeof(route));
    new_route->method = method;

    new_route->uri = malloc(strlen(uri) + 1);
    strcpy(new_route->uri, uri);

    new_route->file_path = malloc(strlen(file_path) + 1);
    strcpy(new_route->file_path, file_path);
    
    server->routes[server->route_count] = new_route;
    server->route_count++;
}

void del_route(route* route) {
    free(route->uri);
    free(route->file_path);
    free(route);
}

int find_route(http_server* server, char* uri, method_t method) {
    for (int i = 0; i < server->route_count; i++) {
        if (strcmp(server->routes[i]->uri, uri) == 0 && server->routes[i]->method == method) {
            return i;
        }
    }
    return -1;
}


