#include "server.h"

#define PORT 1337

int main(void) {
    http_server* server = new_server("127.0.0.1", PORT);

    new_route(server, "/", "./index.html", HTTP_GET);
    new_route(server, "/form", "./form.html", HTTP_GET);
    new_route(server, "/form", "./success.html", HTTP_POST);

    launch_server(server);
    close_server(server);
    
    return 0;
}
