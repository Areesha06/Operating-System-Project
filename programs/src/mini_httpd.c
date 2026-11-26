/*
 * mini_httpd.c - tiny single-request HTTP server (I/O element: sockets).
 *
 * Usage: mini_httpd PORT ROOTDIR
 * Serves exactly ONE request from 127.0.0.1:PORT and then exits, so runs are
 * short and deterministic.
 *   GET /file  -> sends the file with sendfile()            (training run)
 *   GET /      -> sends an HTML directory listing (getdents64) (held-out run)
 *   missing    -> 404
 * The two runs exercise different kernel paths, which is exactly what a
 * trace-only baseline cannot anticipate.
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static void send_str(int c, const char *s) { write(c, s, strlen(s)); }

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s PORT ROOTDIR\n", argv[0]); return 2; }
    int port = atoi(argv[1]);
    if (chdir(argv[2]) != 0) { perror("chdir"); return 1; }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    listen(s, 1);

    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }
    char req[2048] = {0};
    read(c, req, sizeof req - 1);

    char path[1024] = ".";
    sscanf(req, "GET %1000s", path + 1);           /* "/x" -> "./x" */

    struct stat st;
    if (stat(path, &st) != 0) {
        send_str(c, "HTTP/1.0 404 Not Found\r\n\r\nnot found\n");
    } else if (S_ISDIR(st.st_mode)) {
        send_str(c, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<ul>\n");
        DIR *d = opendir(path);
        struct dirent *e;
        while (d && (e = readdir(d)) != NULL) {
            char line[600];
            snprintf(line, sizeof line, "<li>%s</li>\n", e->d_name);
            send_str(c, line);
        }
        if (d) closedir(d);
        send_str(c, "</ul>\n");
    } else {
        int f = open(path, O_RDONLY);
        char hdr[128];
        snprintf(hdr, sizeof hdr, "HTTP/1.0 200 OK\r\nContent-Length: %ld\r\n\r\n", (long)st.st_size);
        send_str(c, hdr);
        off_t off = 0;
        sendfile(c, f, &off, st.st_size);
        close(f);
    }
    close(c);
    close(s);
    return 0;
}
