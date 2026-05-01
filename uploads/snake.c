/*
 * snake.c  —  Multiplayer Snake (up to 4 players) for Termux
 *
 * HOW TO BUILD (Termux):
 *   pkg install clang
 *   clang snake.c -o snake
 *
 * HOW TO RUN:
 *   Server (host):  ./snake
 *   Client (join):  ./snake 192.168.x.x
 *
 * CONTROLS:  W A S D  to move  |  Q to quit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

/* ───────── Config ───────── */
#define MAX_LEN      200
#define MAX_PLAYERS  4
#define MAX_FOOD     8
#define W            60
#define H            22
#define PORT         9999
#define TICK_US      130000    /* ms per tick (lower = faster) */
#define RESPAWN_SECS 5

/* ───────── ANSI colours ───────── */
#define RST  "\033[0m"
#define RED  "\033[31m"
#define GRN  "\033[32m"
#define CYN  "\033[36m"
#define YLW  "\033[33m"
#define PRP  "\033[35m"
#define BLU  "\033[34m"
#define BLD  "\033[1m"

static const char *SNAKE_COLORS[MAX_PLAYERS] = {GRN, CYN, PRP, YLW};
static const char *SNAKE_NAMES[MAX_PLAYERS]  = {"Green","Cyan","Purple","Yellow"};

/* ───────── Data types ───────── */
typedef struct {
    int  x[MAX_LEN], y[MAX_LEN];
    int  len;
    int  dx, dy;
    int  alive;
    int  score;
    long dead_time;
} Snake;

typedef struct {
    Snake players[MAX_PLAYERS];
    int   player_count;
    int   fx[MAX_FOOD], fy[MAX_FOOD];
    int   food_count;
    int   tick;
} GameState;

/* ───────── Terminal raw mode ───────── */
static struct termios _old_term;

static void restore_term(void) {
    tcsetattr(0, TCSANOW, &_old_term);
    printf(RST "\033[?25h");   /* show cursor */
    fflush(stdout);
}

static void raw_mode(void) {
    struct termios t;
    tcgetattr(0, &_old_term);
    t = _old_term;
    t.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(0, TCSANOW, &t);
    atexit(restore_term);
}

/* Non-blocking key read (returns 0 if nothing) */
static int get_key(void) {
    int c = 0;
    struct timeval tv = {0, 0};
    fd_set f;
    FD_ZERO(&f);
    FD_SET(0, &f);
    if (select(1, &f, NULL, NULL, &tv) > 0)
        read(0, &c, 1);
    return c;
}

/* Wait up to `ms` milliseconds for a key */
static int wait_key(int ms) {
    int c = 0;
    struct timeval tv = {0, ms * 1000};
    fd_set f;
    FD_ZERO(&f);
    FD_SET(0, &f);
    if (select(1, &f, NULL, NULL, &tv) > 0)
        read(0, &c, 1);
    return c;
}

/* ───────── Socket helpers ───────── */
static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void set_block(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
}

/* ───────── Game: spawn helpers ───────── */
static void add_food(GameState *g) {
    if (g->food_count >= MAX_FOOD) return;
    g->fx[g->food_count] = rand() % (W - 2) + 1;
    g->fy[g->food_count] = rand() % (H - 2) + 1;
    g->food_count++;
}

static void ensure_food(GameState *g) {
    while (g->food_count < MAX_FOOD)
        add_food(g);
}

static void spawn_snake(Snake *s, int idx) {
    /* Fixed starting positions for each player */
    static const int SX[] = {5,      W-6,  5,    W-6};
    static const int SY[] = {H/2,    H/2,  H/4,  3*H/4};
    static const int DD[] = {1,      -1,   1,    -1};
    s->len = 4;
    s->dx  = DD[idx];
    s->dy  = 0;
    s->alive = 1;
    s->dead_time = 0;
    for (int i = 0; i < 4; i++) {
        s->x[i] = SX[idx] - i * DD[idx];
        s->y[i] = SY[idx];
    }
    /* note: score is NOT reset on respawn */
}

static void init_game(GameState *g, int n) {
    memset(g, 0, sizeof(*g));
    g->player_count = n;
    srand((unsigned)time(NULL));
    for (int i = 0; i < n; i++) spawn_snake(&g->players[i], i);
    ensure_food(g);
}

/* ───────── Game: per-tick update ───────── */
static void move_snake(Snake *s) {
    if (!s->alive) return;
    for (int i = s->len; i > 0; i--) {
        s->x[i] = s->x[i-1];
        s->y[i] = s->y[i-1];
    }
    s->x[0] += s->dx;
    s->y[0] += s->dy;
    /* wrap-around walls */
    if (s->x[0] <= 0)   s->x[0] = W - 2;
    if (s->x[0] >= W-1) s->x[0] = 1;
    if (s->y[0] <= 0)   s->y[0] = H - 2;
    if (s->y[0] >= H-1) s->y[0] = 1;
}

static int head_hits_body(Snake *a, Snake *b, int skip_own_head) {
    int start = skip_own_head ? 1 : 0;
    for (int i = start; i < b->len; i++)
        if (a->x[0] == b->x[i] && a->y[0] == b->y[i])
            return 1;
    return 0;
}

static void do_food(GameState *g, Snake *s) {
    for (int f = 0; f < g->food_count; f++) {
        if (s->x[0] == g->fx[f] && s->y[0] == g->fy[f]) {
            if (s->len < MAX_LEN - 1) s->len++;
            s->score += 10;
            /* remove eaten food and fill gap */
            g->fx[f] = g->fx[g->food_count - 1];
            g->fy[f] = g->fy[g->food_count - 1];
            g->food_count--;
            ensure_food(g);
            break;
        }
    }
}

static void apply_dir(Snake *s, char key) {
    if ((key == 'w' || key == 'W') && s->dy == 0) { s->dx =  0; s->dy = -1; }
    if ((key == 's' || key == 'S') && s->dy == 0) { s->dx =  0; s->dy =  1; }
    if ((key == 'a' || key == 'A') && s->dx == 0) { s->dx = -1; s->dy =  0; }
    if ((key == 'd' || key == 'D') && s->dx == 0) { s->dx =  1; s->dy =  0; }
}

static void update_game(GameState *g) {
    /* Move */
    for (int i = 0; i < g->player_count; i++)
        move_snake(&g->players[i]);

    /* Eat food */
    for (int i = 0; i < g->player_count; i++)
        if (g->players[i].alive)
            do_food(g, &g->players[i]);

    /* Collision: head vs all bodies (including own body, skip own head) */
    for (int i = 0; i < g->player_count; i++) {
        if (!g->players[i].alive) continue;
        for (int j = 0; j < g->player_count; j++) {
            if (!g->players[j].alive) continue;
            int skip_head = (i == j);
            if (head_hits_body(&g->players[i], &g->players[j], skip_head)) {
                g->players[i].alive = 0;
                g->players[i].dead_time = time(NULL);
                break;
            }
        }
    }

    /* Respawn */
    for (int i = 0; i < g->player_count; i++) {
        Snake *s = &g->players[i];
        if (!s->alive && time(NULL) - s->dead_time >= RESPAWN_SECS) {
            int saved_score = s->score;
            spawn_snake(s, i);
            s->score = saved_score;
        }
    }

    g->tick++;
}

/* ───────── Rendering ───────── */
static void draw(const GameState *g, int me) {
    printf("\033[H\033[?25l"); /* home + hide cursor */

    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            /* Border */
            if (x == 0 || x == W-1 || y == 0 || y == H-1) {
                printf(CYN "#" RST);
                continue;
            }

            int drawn = 0;

            /* Food */
            for (int f = 0; f < g->food_count && !drawn; f++) {
                if (g->fx[f] == x && g->fy[f] == y) {
                    printf(RED "●" RST);
                    drawn = 1;
                }
            }

            /* Snakes */
            for (int p = 0; p < g->player_count && !drawn; p++) {
                const Snake *s = &g->players[p];
                for (int i = 0; i < s->len && !drawn; i++) {
                    if (s->x[i] == x && s->y[i] == y) {
                        printf("%s%c" RST,
                               SNAKE_COLORS[p],
                               i == 0 ? 'O' : 'o');
                        drawn = 1;
                    }
                }
            }

            if (!drawn) printf(" ");
        }
        printf("\n");
    }

    /* Status bar */
    printf(BLD "You: %sPlayer %d" RST BLD " | " RST, SNAKE_COLORS[me], me + 1);
    for (int i = 0; i < g->player_count; i++) {
        const Snake *s = &g->players[i];
        printf("%s%sP%d %3d pts%s%s  " RST,
               SNAKE_COLORS[i],
               i == me ? BLD : "",
               i + 1,
               s->score,
               s->alive ? "" : " 💀",
               RST);
    }
    printf("  WASD=move  Q=quit\r\n");
    fflush(stdout);
}

/* ═══════════════════════════════════
 *  SERVER
 * ═══════════════════════════════════*/
static int server_main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, MAX_PLAYERS);
    set_nonblock(srv);

    /* Auto-detect local IP via UDP trick (no permissions needed) */
    char my_ip[64] = "unknown";
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct sockaddr_in test;
            memset(&test, 0, sizeof(test));
            test.sin_family = AF_INET;
            test.sin_port   = htons(80);
            inet_pton(AF_INET, "8.8.8.8", &test.sin_addr);
            if (connect(fd, (struct sockaddr *)&test, sizeof(test)) == 0) {
                struct sockaddr_in local;
                socklen_t len = sizeof(local);
                if (getsockname(fd, (struct sockaddr *)&local, &len) == 0)
                    strncpy(my_ip, inet_ntoa(local.sin_addr), sizeof(my_ip)-1);
            }
            close(fd);
        }
    }

    printf("\033[2J\033[H");
    printf(BLD GRN "╔══════════════════════════════╗\n");
    printf("║    SNAKE  MULTIPLAYER  🐍    ║\n");
    printf("╚══════════════════════════════╝\n" RST);
    printf("\n");
    printf(BLD YLW "  ► Your IP address: %s\n\n" RST, my_ip);
    printf(CYN "  Clients join with:\n" RST);
    printf("    ./snake %s\n\n", my_ip);
    printf("  Waiting for players to connect...\n");
    printf(GRN "  Press ENTER to start the game!\n\n" RST);

    int clients[MAX_PLAYERS - 1];
    int n_clients = 0;

    /* Lobby: accept connections until Enter is pressed */
    while (1) {
        /* Check for new connections */
        int c = accept(srv, NULL, NULL);
        if (c > 0 && n_clients < MAX_PLAYERS - 1) {
            unsigned char pid = (unsigned char)(n_clients + 1);
            send(c, &pid, 1, 0);          /* tell client their player ID */
            set_nonblock(c);
            clients[n_clients++] = c;
            printf(CYN "  ✔ Player %d connected! (%d/%d players)\n" RST,
                   pid + 1, n_clients + 1, MAX_PLAYERS);
            fflush(stdout);
        }

        /* Check for Enter key on stdin */
        fd_set f;
        struct timeval tv = {0, 30000};
        FD_ZERO(&f); FD_SET(0, &f);
        if (select(1, &f, NULL, NULL, &tv) > 0) {
            char ch;
            if (read(0, &ch, 1) > 0 && (ch == '\n' || ch == '\r'))
                break;
        }
    }

    int total = n_clients + 1;   /* server is player 0 */
    printf("\n" BLD "Starting with %d player(s)!\n" RST, total);
    sleep(1);

    raw_mode();
    printf("\033[2J");

    GameState g;
    init_game(&g, total);

    while (1) {
        /* ── Server player 0 input ── */
        int c = get_key();
        if (c == 'q' || c == 'Q') break;
        if (c) apply_dir(&g.players[0], (char)c);

        /* ── Receive inputs from each client ── */
        for (int i = 0; i < n_clients; i++) {
            char buf[16];
            int r = recv(clients[i], buf, sizeof(buf), 0);
            if (r > 0) {
                for (int k = 0; k < r; k++)
                    apply_dir(&g.players[i + 1], buf[k]);
            }
        }

        update_game(&g);
        draw(&g, 0);

        /* ── Broadcast state ── */
        for (int i = 0; i < n_clients; i++)
            send(clients[i], &g, sizeof(g), 0);

        usleep(TICK_US);
    }

    printf("\033[2J\033[H" BLD "Game over!\n" RST);
    for (int i = 0; i < total; i++)
        printf("  %sPlayer %d: %d pts\n" RST, SNAKE_COLORS[i], i+1, g.players[i].score);

    return 0;
}

/* ═══════════════════════════════════
 *  CLIENT
 * ═══════════════════════════════════*/
static int client_main(char *ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        return 1;
    }

    printf("Connecting to %s:%d ...\n", ip, PORT);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    /* Receive assigned player ID */
    unsigned char me_id = 0;
    if (recv(sock, &me_id, 1, 0) != 1) {
        fprintf(stderr, "Failed to receive player ID\n");
        return 1;
    }
    if (me_id >= MAX_PLAYERS) me_id = MAX_PLAYERS - 1;

    printf(BLD "%sConnected as Player %d (%s)!\n" RST,
           SNAKE_COLORS[me_id], me_id + 1, SNAKE_NAMES[me_id]);
    printf("Waiting for server to start the game...\n");

    raw_mode();
    set_nonblock(sock);

    /* Block until first state arrives */
    GameState g;
    memset(&g, 0, sizeof(g));

    /* Wait for first packet */
    set_block(sock);
    recv(sock, &g, sizeof(g), 0);
    set_nonblock(sock);

    printf("\033[2J");

    while (1) {
        /* Read and send key */
        int c = get_key();
        if (c == 'q' || c == 'Q') break;
        if (c) {
            char ch = (char)c;
            send(sock, &ch, 1, 0);
        }

        /* Receive new state (non-blocking) */
        ssize_t r = recv(sock, &g, sizeof(g), 0);
        if (r == 0) {
            printf("\033[2J\033[HServer closed. Game over.\n");
            break;
        }
        if (r == (ssize_t)sizeof(g))
            draw(&g, me_id);

        usleep(TICK_US / 4);  /* poll 4x per tick for smooth key response */
    }

    printf("\033[2J\033[HDisconnected. Final scores:\n");
    for (int i = 0; i < g.player_count; i++)
        printf("  %sPlayer %d: %d pts\n" RST, SNAKE_COLORS[i], i+1, g.players[i].score);

    return 0;
}

/* ═══════════════════════════════════
 *  ENTRY POINT
 * ═══════════════════════════════════*/
int main(int argc, char *argv[]) {
    if (argc == 1)
        return server_main();
    else if (argc == 2)
        return client_main(argv[1]);
    else {
        fprintf(stderr, "Usage:\n  Server: %s\n  Client: %s <server_ip>\n",
                argv[0], argv[0]);
        return 1;
    }
}
