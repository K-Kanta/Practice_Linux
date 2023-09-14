#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#define _GNU_SOURCE
#include <getopt.h>

/****** Constants ********************************************************/

#define SERVER_NAME "LittleHTTP"
#define SERVER_VERSION "1.0"
#define HTTP_MINOR_VERSION 0
#define BLOCK_BUF_SIZE 1024
#define LINE_BUF_SIZE 4096
#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define MAX_BACKLOG 5
#define DEFAULT_PORT "80"

/****** Data Type Definitions ********************************************/

struct HTTPHeaderField {
    char *name;
    char *value;
    struct HTTPHeaderField *next;
};

struct HTTPRequest {
    int protocol_minor_version;
    char *method;
    char *path;
    struct HTTPHeaderField *header;
    char *body;
    long length;
};

struct FileInfo {
    char *path;
    long size;
    int ok;
};

/****** Function Prototypes **********************************************/

static void setup_environment(char *root, char *user, char *group);
typedef void (*sighandler_t)(int);
static void install_signal_handlers(void);
static void trap_signal(int sig, sighandler_t handler);
static void detach_children(void);
static void signal_exit(int sig);
static void noop_handler(int sig);
static void become_daemon(void);
static int listen_socket(char *port);
static void server_main(int server, char *docroot);
static void service(FILE *in, FILE *out, char *docroot);
static struct HTTPRequest* read_request(FILE *in);
static void read_request_line(struct HTTPRequest *req, FILE *in);
static struct HTTPHeaderField* read_header_field(FILE *in);
static void upcase(char *str);
static void free_request(struct HTTPRequest *req);
static long content_length(struct HTTPRequest *req);
static char* lookup_header_field_value(struct HTTPRequest *req, char *name);
static void respond_to(struct HTTPRequest *req, FILE *out, char *docroot);
static void do_file_response(struct HTTPRequest *req, FILE *out, char *docroot);
static void method_not_allowed(struct HTTPRequest *req, FILE *out);
static void not_implemented(struct HTTPRequest *req, FILE *out);
static void not_found(struct HTTPRequest *req, FILE *out);
static void output_common_header_fields(struct HTTPRequest *req, FILE *out, char *status);
static struct FileInfo* get_fileinfo(char *docroot, char *path);
static char* build_fspath(char *docroot, char *path);
static void free_fileinfo(struct FileInfo *info);
static char* guess_content_type(struct FileInfo *info);
static void* xmalloc(size_t sz);
static void log_exit(const char *fmt, ...);

/****** Functions ********************************************************/

#define USAGE "Usage: %s [--port=n] [--chroot --user=u --group=g] [--debug] <docroot>\n"

static int debug_mode = 0; // デフォルトはデバッグモードなし

static struct option longopts[] = {
    {"debug",  no_argument,       &debug_mode, 1}, 
    {"chroot", no_argument,       NULL, 'c'},
    {"user",   required_argument, NULL, 'u'},
    {"group",  required_argument, NULL, 'g'},
    {"port",   required_argument, NULL, 'p'},
    {"help",   no_argument,       NULL, 'h'},
    {0, 0, 0, 0}
}; // getopt_long()に渡すための配列を初期化。左から、オプションの名前、引数を取るかどうか、オプションが存在する場合に設定するフラグへのポインタ、オプションの省略名を表す。

int
main(int argc, char *argv[])
{
    int server_fd; // サーバーのファイルディスクリプタ（FD: ファイルを識別するための目印）
    char *port = NULL; // ポート番号
    char *docroot; // ドキュメントルート
    int do_chroot = 0; // chrootの実行フラグ
    char *user = NULL; // ユーザー名
    char *group = NULL; // グループ名
    int opt; // コマンドライン変数解析のための一時変数

    while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) { // getopt_long関数がコマンドライン引数を解析し、指定されたオプションによって以下の処理を実行
        switch (opt) {
        case 0:
            break;
        case 'c':
            do_chroot = 1; // --chroot -> do_chroot変数を1に設定
            break;
        case 'u':
            user = optarg; // --user -> ユーザー名指定
            break;
        case 'g':
            group = optarg; // --group -> グループ名指定
            break;
        case 'p':
            port = optarg; // --port -> ポート指定
            break;
        case 'h':
            fprintf(stdout, USAGE, argv[0]); // --help -> helpメッセージ表示
            exit(0); // 終了
        case '?':
            fprintf(stderr, USAGE, argv[0]); // --? -> USAGE表示
            exit(1);
        }
    }
    if (optind != argc - 1) {
        fprintf(stderr, USAGE, argv[0]);
        exit(1);
    } // 残りの引数が１つであることを確認
    docroot = argv[optind]; // 出出力するファイルがあるドキュメントルートのパスを取得し、docrootに格納

    if (do_chroot) {
        setup_environment(docroot, user, group);
        docroot = "";
    } // do_chrootのフラグがセットされる場合、ルートディレクトリを変更し、セキュリティを向上
    install_signal_handlers(); // サーバーがシグナルを適切の処理できるようシグナルハンドラを設定
    server_fd = listen_socket(port); // 指定されたポートでリスニングソケットを作成し、クライアントからの接続をも待つ
    if (!debug_mode) {
        openlog(SERVER_NAME, LOG_PID|LOG_NDELAY, LOG_DAEMON); // debug_modeがセットされていない場合、openlog関数を使用してシステムログにエントリを作成
        become_daemon(); // become_daemon関数を呼び出しプログラムをデーモン化
    } 
    server_main(server_fd, docroot); // HTTPリクエストの送受信を行う関数server_main()を呼び出し
    exit(0); // サーバーのメイン処理が終了したらプログラム終了
}

static void
setup_environment(char *root, char *user, char *group) // chroot実行時に呼び出し
{
    struct passwd *pw;
    struct group *gr;

    if (!user || !group) { // ユーザー名とグループ名が指定されているかを確認
        fprintf(stderr, "use both of --user and --group\n");
        exit(1);
    }

    gr = getgrnam(group); // グループ名に関する情報を取得（gr_name:グループ名, gr_passwd：パスワード, gr_gid：グループID, gr_mem:メンバーであるユーザー名のリスト）
    if (!gr) {
        fprintf(stderr, "no such group: %s\n", group);
        exit(1);
    }
    if (setgid(gr->gr_gid) < 0) { // プロセスの実効グループIDを指定されたグループのグループIDに変更し、プロセスに指定されたグループの権限を付与
        perror("setgid(2)");
        exit(1);
    }
    if (initgroups(user, gr->gr_gid) < 0) { // ユーザーが所属するすべての補助グループの初期化し、プロセスに指定された補助グループの権限を付与
        perror("initgroups(2)");
        exit(1);
    }

    pw = getpwnam(user); // ユーザー情報の取得（pw_name:ユーザー名, pw_passwd：パスワード, pw_uid：ユーザーID, pw_gid: プライマリグループIDなど）
    if (!pw) {
        fprintf(stderr, "no such user: %s\n", user);
        exit(1);
    }
    chroot(root); //プロセスのルートディレクトリを指定されたrootに変更し、セキュリティ上の分離をする
    if (setuid(pw->pw_uid) < 0) { //　プロセスの実効ユーザーIDを指定されたユーザーのユーザーIDに変更し、プロセスに指定されたユーザーの権限を付与
        perror("setuid(2)");
        exit(1);
    }
}

static void
become_daemon(void)
{
    int n;

    if (chdir("/") < 0) // カレントディレクトリをルートディレクトリに指定し、プロセスがどのディレクトリにも関連付けられなくする
        log_exit("chdir(2) failed: %s", strerror(errno));
    freopen("/dev/null", "r", stdin); // 標準入力を/dev/null（空のデバイスファイル）にリダイレクト。これによりデーモンプロセスは標準入力からの入力を受け取らない
    freopen("/dev/null", "w", stdout); // 標準出力を/dev/nullにリダイレクト。デーモンプロセスは標準出力に出力しなくなる
    freopen("/dev/null", "w", stderr); // 標準エラー出力も/dev/nullにリダイレクト。デーモンプロセスはエラーメッセージを表示しなくなる
    n = fork(); //新しいプロセスをフォーク
    if (n < 0) log_exit("fork(2) failed: %s", strerror(errno)); 
    if (n != 0) _exit(0); // 親プロセスの終了
    if (setsid() < 0) log_exit("setsid(2) failed: %s", strerror(errno)); // 新しいセッションの作成とセッションIDの設定。デーモンプロセスを制御端末から独立
}

static void
install_signal_handlers(void)
{
    trap_signal(SIGTERM, signal_exit); // SIGTERMを捕捉し、signal_exit()を呼び出すようなシグナルハンドラを設定。
    detach_children(); // 子プロセスを親プロセスから独立させる。これにより親プロセスが終了しても子プロセスは影響を受けず動作可能
}

static void
trap_signal(int sig, sighandler_t handler)
{
    struct sigaction act;

    act.sa_handler = handler; // シグナルが発生した時に呼び出される
    sigemptyset(&act.sa_mask); // ハンドラ関数が自身のシグナル処理中に同じシグナルを受け取らないようにする
    act.sa_flags = SA_RESTART; // システムコールが中断された場合に再試行
    if (sigaction(sig, &act, NULL) < 0) { // 指定されたシグナルとactを関連付け
        log_exit("sigaction() failed: %s", strerror(errno));
    }
} 

static void
detach_children(void)
{
    struct sigaction act;

    act.sa_handler = noop_handler; 
    sigemptyset(&act.sa_mask); 
    act.sa_flags = SA_RESTART | SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &act, NULL) < 0) {
        log_exit("sigaction() failed: %s", strerror(errno));
    }
} // 子プロセスをデタッチし、子プロセスがゾンビプロセスとして残るのを防ぐ

static void
signal_exit(int sig)
{
    log_exit("exit by signal %d", sig);
} // エラー出力

static void
noop_handler(int sig)
{
    ;
} // 空のハンドラ関数。シグナルが発生したことを検出するために存在。

static int
listen_socket(char *port)
{
    struct addrinfo hints, *res, *ai;
    int err;

    memset(&hints, 0, sizeof(struct addrinfo)); // hints構造体の0初期化。アドレス情報の取得方法を示すヒントがクリアされる
    hints.ai_family = AF_INET; // IPv4アドレスファミリを設定
    hints.ai_socktype = SOCK_STREAM; // TCPを設定
    hints.ai_flags = AI_PASSIVE; // サーバー用のソケット設定
    if ((err = getaddrinfo(NULL, port, &hints, &res)) != 0) // 指定されてポート番号とhint構造体からアドレス情報を取得
        log_exit(gai_strerror(err));
    for (ai = res; ai; ai = ai->ai_next) {
        int sock;

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol); // aiの情報からソケットの作成
        if (sock < 0) continue; // ソケット作成失敗時、次のアドレス情報に進む
        if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) { // ソケットを指定されたアドレスにバインド
            close(sock);
            continue;
        }
        if (listen(sock, MAX_BACKLOG) < 0) { // ソケットをリスニングモードに設定
            close(sock);
            continue;
        }
        freeaddrinfo(res); // アドレス情報のリストを解放。メモリリークを防ぐ。
        return sock;
    }
    log_exit("failed to listen socket");
    return -1;  /* NOT REACH */
}

static void
server_main(int server_fd, char *docroot)
{
    for (;;) { // 無限ループによりサーバーが常に接続を待ち受ける状態に設定
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof addr;
        int sock;
        int pid;

        sock = accept(server_fd, (struct sockaddr*)&addr, &addrlen); // クライアントからの接続を受け入れる。接続の詳細な情報はaddrに格納。sockにソケットディスクリプタを格納。
        if (sock < 0) log_exit("accept(2) failed: %s", strerror(errno)); // acceptエラーメッセージ
        pid = fork(); // 新しい子プロセスの生成。成功時に０を返す
        if (pid < 0) exit(3);
        if (pid == 0) {   /* child */
            FILE *inf = fdopen(sock, "r");
            FILE *outf = fdopen(sock, "w"); 

            service(inf, outf, docroot); // service()でHTTPリクエストの読み込みとHTTPレスポンスを作成を行う
            exit(0);
        }
        close(sock); // 親プロセスは接続済みのソケットをクローズし、新しい接続を受け入れる準備をする
    }
}

static void
service(FILE *in, FILE *out, char *docroot)
{
    struct HTTPRequest *req;

    req = read_request(in); // リクエストを読み込み
    respond_to(req, out, docroot); // レスポンスを生成
    free_request(req); // メモリ解放
}

static struct HTTPRequest*
read_request(FILE *in)
{
    struct HTTPRequest *req;
    struct HTTPHeaderField *h;

    req = xmalloc(sizeof(struct HTTPRequest)); // HTTPRequest分のメモリ割り当て
    read_request_line(req, in); // リクエストを読み込み、req構造体にmethod, path, protocol_minor_versionを取得
    req->header = NULL; // req構造体のheaderを初期化
    while (h == read_header_field(in)) { // リクエストを読み込み、headerを取得
        h->next = req->header;
        req->header = h;
    }
    req->length = content_length(req); // bodyの有無・長さを確認
    if (req->length != 0) {
        if (req->length > MAX_REQUEST_BODY_LENGTH)
            log_exit("request body too long");
        req->body = xmalloc(req->length);
        if (fread(req->body, req->length, 1, in) < 1)
            log_exit("failed to read request body");
    } else {
        req->body = NULL;
    }
    return req;
}

static void
read_request_line(struct HTTPRequest *req, FILE *in)
{
    char buf[LINE_BUF_SIZE];
    char *path, *p;

    if (!fgets(buf, LINE_BUF_SIZE, in)) // fgetでリクエストを１行読み込み（maxサイズがLINE_BUF_SIZE）、bufに最初の文字を割り当て
        log_exit("no request line");
    p = strchr(buf, ' ');       /* p (1) */  // bufの最初の' 'のポインタを取得
    if (!p) log_exit("parse error on request line (1): %s", buf);
    *p++ = '\0'; // ' 'を'\0'に置換しポインタの位置を１つ進める
    req->method = xmalloc(p - buf); // req構造体のmethodにmethodの大きさ分のメモリを割り当て
    strcpy(req->method, buf); // req構造体のmethodにmethodの部分を格納
    upcase(req->method); // 大文字化

    path = p; // pathの開始地点の設定
    p = strchr(path, ' ');      /* p (2) */  // pathから最初の' 'のポインタを取得
    if (!p) log_exit("parse error on request line (2): %s", buf);
    *p++ = '\0'; // ' 'を'\0'に置換しポインタを１つ進める
    req->path = xmalloc(p - path); // req構造体のpathにpathの大きさ分のメモリを割り当て
    strcpy(req->path, path); // req構造体のpathにpathを格納

    if (strncasecmp(p, "HTTP/1.", strlen("HTTP/1.")) != 0) // 前からstrlen("HTTP/1.")の長さで、pと"HTTP/1."を比較
        log_exit("parse error on request line (3): %s", buf);
    p += strlen("HTTP/1.");     /* p (3) */   // "HTTP/1."の先までポインタを進め、minor_versionを取得
    req->protocol_minor_version = atoi(p); // minor_versionを数値化後、reqのprotocol_minor_versionに格納
}

static struct HTTPHeaderField*
read_header_field(FILE *in)
{
    struct HTTPHeaderField *h;
    char buf[LINE_BUF_SIZE];
    char *p;

    if (!fgets(buf, LINE_BUF_SIZE, in)) // fgetでリクエストを１行読み込み（maxサイズがLINE_BUF_SIZE）、bufに最初の文字を割り当て
        log_exit("failed to read request header field: %s", strerror(errno));
    if ((buf[0] == '\n') || (strcmp(buf, "\r\n") == 0))  // 改行を検索し、headerの終端を確認
        return NULL;

    p = strchr(buf, ':'); // bufの最初の':'のポインタを取得
    if (!p) log_exit("parse error on request header field: %s", buf);
    *p++ = '\0'; // ' 'を'\0'に置換しポインタを一つ進める
    h = xmalloc(sizeof(struct HTTPHeaderField)); // hにHTTPHeaderField分のメモリを割り当て
    h->name = xmalloc(p - buf); // h構造体のnameにメモリ割り当て
    strcpy(h->name, buf); // h構造体のnameにname部分を格納

    p += strspn(p, " \t"); // ポインタの位置をheaderのvalueの位置まで進める
    h->value = xmalloc(strlen(p) + 1);  // メモリ割り当て
    strcpy(h->value, p); // headerのvalueをh構造体のvalueに格納

    return h;
}

static void
upcase(char *str)
{
    char *p;

    for (p = str; *p; p++) {
        *p = (char)toupper((int)*p);
    }
} // 大文字化

static void
free_request(struct HTTPRequest *req)
{
    struct HTTPHeaderField *h, *head;

    head = req->header;
    while (head) {
        h = head;
        head = head->next;
        free(h->name);
        free(h->value);
        free(h);
    }
    free(req->method);
    free(req->path);
    free(req->body);
    free(req);
} // メモリの解放

static long
content_length(struct HTTPRequest *req)
{
    char *val;
    long len;
    
    val = lookup_header_field_value(req, "Content-Length"); // bodyのvalueを返す（なければNULL）
    if (!val) return 0;
    len = atol(val); // valueの長さを数値化
    if (len < 0) log_exit("negative Content-Length value");
    return len;
} // 文字列の長さを確認

static char*
lookup_header_field_value(struct HTTPRequest *req, char *name)
{
    struct HTTPHeaderField *h;

    for (h = req->header; h; h = h->next) {
        if (strcasecmp(h->name, name) == 0) // name="Content-Length"があれば内容valueを返す
            return h->value;
    }
    return NULL; // なければ何も返さない
}

static void
respond_to(struct HTTPRequest *req, FILE *out, char *docroot)
{
    if (strcmp(req->method, "GET") == 0) // GETオプションを確認した時do_file_request()を起動
        do_file_response(req, out, docroot);
    else if (strcmp(req->method, "HEAD") == 0) // HEADオプションを確認した時do_file_request()を起動
        do_file_response(req, out, docroot);
    else if (strcmp(req->method, "POST") == 0) // POSTプションを確認した時method_not_allowed()を起動
        method_not_allowed(req, out);
    else
        not_implemented(req, out); // その他のオプションを確認した時はmethod_not_allowed()を起動
}

static void
do_file_response(struct HTTPRequest *req, FILE *out, char *docroot)
{
    struct FileInfo *info;

    info = get_fileinfo(docroot, req->path); // path, size, okを取得
    if (!info->ok) {
        free_fileinfo(info); // 失敗した時、メモリを解放
        not_found(req, out); // 404 not foundを表示
        return;
    }
    output_common_header_fields(req, out, "200 OK"); // HTTP/1.0 200OK, Date, Server, Connectionを取得
    fprintf(out, "Content-Length: %ld\r\n", info->size); // 出力するコンテンツの長さを出力
    fprintf(out, "Content-Type: %s\r\n", guess_content_type(info)); // 出力するコンテンツのタイプを出力
    fprintf(out, "\r\n"); // 改行の追加
    if (strcmp(req->method, "HEAD") != 0) { // HEADメソッド出ない時
        int fd;
        char buf[BLOCK_BUF_SIZE];
        ssize_t n;

        fd = open(info->path, O_RDONLY); // file open
        if (fd < 0)
            log_exit("failed to open %s: %s", info->path, strerror(errno));
        for (;;) {
            n = read(fd, buf, BLOCK_BUF_SIZE); // fileをブロック単位で読む
            if (n < 0)
                log_exit("failed to read %s: %s", info->path, strerror(errno));
            if (n == 0)
                break;
            if (fwrite(buf, 1, n, out) < n) // fileをソケットに書き込み
                log_exit("failed to write to socket");
        }
        close(fd);
    }
    fflush(out); // 出力をソケットにフラッシュ
    free_fileinfo(info); // メモリ解放
}

static void
method_not_allowed(struct HTTPRequest *req, FILE *out)
{
    output_common_header_fields(req, out, "405 Method Not Allowed");
    fprintf(out, "Content-Type: text/html\r\n");
    fprintf(out, "\r\n");
    fprintf(out, "<html>\r\n");
    fprintf(out, "<header>\r\n");
    fprintf(out, "<title>405 Method Not Allowed</title>\r\n");
    fprintf(out, "<header>\r\n");
    fprintf(out, "<body>\r\n");
    fprintf(out, "<p>The request method %s is not allowed</p>\r\n", req->method);
    fprintf(out, "</body>\r\n");
    fprintf(out, "</html>\r\n");
    fflush(out);
} // 未実装エラー

static void
not_implemented(struct HTTPRequest *req, FILE *out)
{
    output_common_header_fields(req, out, "501 Not Implemented");
    fprintf(out, "Content-Type: text/html\r\n");
    fprintf(out, "\r\n");
    fprintf(out, "<html>\r\n");
    fprintf(out, "<header>\r\n");
    fprintf(out, "<title>501 Not Implemented</title>\r\n");
    fprintf(out, "<header>\r\n");
    fprintf(out, "<body>\r\n");
    fprintf(out, "<p>The request method %s is not implemented</p>\r\n", req->method);
    fprintf(out, "</body>\r\n");
    fprintf(out, "</html>\r\n");
    fflush(out);
} // 未実装エラー

static void
not_found(struct HTTPRequest *req, FILE *out)
{
    output_common_header_fields(req, out, "404 Not Found");
    fprintf(out, "Content-Type: text/html\r\n");
    fprintf(out, "\r\n");
    if (strcmp(req->method, "HEAD") != 0) {
        fprintf(out, "<html>\r\n");
        fprintf(out, "<header><title>Not Found</title><header>\r\n");
        fprintf(out, "<body><p>File not found</p></body>\r\n");
        fprintf(out, "</html>\r\n");
    }
    fflush(out);
} // not found エラー

#define TIME_BUF_SIZE 64

static void
output_common_header_fields(struct HTTPRequest *req, FILE *out, char *status)
{
    time_t t;
    struct tm *tm;
    char buf[TIME_BUF_SIZE];

    t = time(NULL);
    tm = gmtime(&t);
    if (!tm) log_exit("gmtime() failed: %s", strerror(errno));
    strftime(buf, TIME_BUF_SIZE, "%a, %d %b %Y %H:%M:%S GMT", tm);
    fprintf(out, "HTTP/1.%d %s\r\n", HTTP_MINOR_VERSION, status);
    fprintf(out, "Date: %s\r\n", buf);
    fprintf(out, "Server: %s/%s\r\n", SERVER_NAME, SERVER_VERSION);
    fprintf(out, "Connection: close\r\n");
}

static struct FileInfo*
get_fileinfo(char *docroot, char *urlpath)
{
    struct FileInfo *info;
    struct stat st;

    info = xmalloc(sizeof(struct FileInfo)); // fileInfo分のメモリ割り当て
    info->path = build_fspath(docroot, urlpath); // フルパスを作成
    info->ok = 0; 
    if (lstat(info->path, &st) < 0) return info; // stにファイルの種類、さいうz、パーミッションを格納
    if (!S_ISREG(st.st_mode)) return info; // ファイルが存在し、通常のファイルである時
    info->ok = 1; // okフラグ
    info->size = st.st_size; // ファイルサイズ
    return info;
} // file情報の取得

static char *
build_fspath(char *docroot, char *urlpath)
{
    char *path;

    path = xmalloc(strlen(docroot) + 1 + strlen(urlpath) + 1);
    sprintf(path, "%s/%s", docroot, urlpath); // フルパスを構築
    return path;
}

static void
free_fileinfo(struct FileInfo *info)
{
    free(info->path);
    free(info);
} // メモリ解放

static char*
guess_content_type(struct FileInfo *info)
{
    return "text/html";   /* FIXME */
} // コンテンツのタイプを指定

static void*
xmalloc(size_t sz)
{
    void *p;

    p = malloc(sz);
    if (!p) log_exit("failed to allocate memory");
    return p;
} // メモリ割り当て

static void
log_exit(const char *fmt, ...) // 可変長文字列を取得
{
    va_list ap;

    va_start(ap, fmt);
    if (debug_mode) {
        vfprintf(stderr, fmt, ap); // debug_modeが有効の時、ログメッセージを標準出力に表示
        fputc('\n', stderr);
    }
    else {
        vsyslog(LOG_ERR, fmt, ap); // debug_modeが無効の時、vsyslogでシステムログにメッセージを書き込み
    }
    va_end(ap);
    exit(1); // 異常終了
}