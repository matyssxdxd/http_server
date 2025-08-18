#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>

typedef enum {
    HEADER_CONTENT_LENGTH,
    HEADER_CONTENT_TYPE,
    HEADER_CONNECTION,
    HEADER_USER_AGENT,
    HEADER_ACCEPT,
    HEADER_AUTHORIZATION,
    HEADER_UNKNOWN
} header_t;

typedef enum { 
    HTTP_GET = 1, 
    HTTP_POST 
} method_t;

typedef enum { 
    UNKNOWN = -1,
    OK = 200, 
    NOT_FOUND = 404,
    BAD_REQUEST = 400
} status_t;

typedef struct http_header {
    header_t type;
    char* name;
    char* value;
} http_header;

typedef struct http_request {
    method_t method;
    char* uri;
    char* version;
    http_header** headers;
    int header_count;
    char* body;
    int body_length;
} http_request;

typedef struct http_response {
    char* version;
    status_t status_code;
    char* phrase;
    http_header** headers;
    int header_count;
    char* body;
} http_response;

typedef struct pairs {
    char** key;
    char** value;
    int len;
} pairs;

typedef struct route {
    method_t method;
    char* uri;
    char* file_path;
} route;

typedef struct http_server {
    int fd;
    struct sockaddr_in addr;
    route** routes;
    int route_count;
} http_server;

method_t method_str_to_enum(char* method);

http_header* new_header(header_t type, char* name, char* value);
void del_header(http_header* head);
header_t get_header_type(const char* name); 
char* get_header_value(http_request* req, const header_t type);

http_request* new_request(); 
void add_request_header(http_request* req, http_header* head); 
void del_request(http_request* req);
http_request* parse_request(char* rbuf);

http_response* new_response();
void add_default_headers(http_response* res); 
http_response* bad_request_response();
http_response* not_found_response();
http_response* ok_response(char* body); 
void del_response(http_response* res); 
http_response* handle_GET_request(http_server* server, http_request* req);
http_response* handle_POST_request(http_request* req);
http_response* handle_request(http_server* server, http_request* req);
char* response_to_string(http_response* res);
    
http_server* new_server(char* addr, int port);
void launch_server(http_server* server); 
void close_server(http_server* server); 
void new_route(http_server* server, char* uri, char* file_path, method_t method); 
void del_route(route* route);
int find_route(http_server* server, char* uri, method_t method); 

#endif // SERVER_H
