#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <sys/select.h>

#define W 15
#define H 25
#define GRAVITY 300000
#define LOCK_DELAY 8

int field[H][W];
int score = 0;
const char *C[8] = {
    "  ",
    "\033[46m  \033[0m",
    "\033[43m  \033[0m",
    "\033[45m  \033[0m",
    "\033[41m  \033[0m",
    "\033[44m  \033[0m",
    "\033[42m  \033[0m",
    "\033[41m  \033[0m"
};
int T[7][4][4][4] = {
{{{0,0,0,0},{1,1,1,1},{0,0,0,0},{0,0,0,0}},
 {{0,0,1,0},{0,0,1,0},{0,0,1,0},{0,0,1,0}},
 {{0,0,0,0},{1,1,1,1},{0,0,0,0},{0,0,0,0}},
 {{0,0,1,0},{0,0,1,0},{0,0,1,0},{0,0,1,0}}},

{{{1,1,0,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}},
 {{1,1,0,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}},
 {{1,1,0,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}},
 {{1,1,0,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}}},

{{{0,1,0,0},{1,1,1,0},{0,0,0,0},{0,0,0,0}},
 {{0,1,0,0},{0,1,1,0},{0,1,0,0},{0,0,0,0}},
 {{0,0,0,0},{1,1,1,0},{0,1,0,0},{0,0,0,0}},
 {{0,1,0,0},{1,1,0,0},{0,1,0,0},{0,0,0,0}}},

{{{1,0,0,0},{1,1,1,0},{0,0,0,0},{0,0,0,0}},
 {{0,1,1,0},{0,1,0,0},{0,1,0,0},{0,0,0,0}},
 {{0,0,0,0},{1,1,1,0},{0,0,1,0},{0,0,0,0}},
 {{0,1,0,0},{0,1,0,0},{1,1,0,0},{0,0,0,0}}},

{{{0,0,1,0},{1,1,1,0},{0,0,0,0},{0,0,0,0}},
 {{0,1,0,0},{0,1,0,0},{0,1,1,0},{0,0,0,0}},
 {{0,0,0,0},{1,1,1,0},{1,0,0,0},{0,0,0,0}},
 {{1,1,0,0},{0,1,0,0},{0,1,0,0},{0,0,0,0}}},

{{{0,1,1,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}},
 {{0,1,0,0},{0,1,1,0},{0,0,1,0},{0,0,0,0}},
 {{0,1,1,0},{1,1,0,0},{0,0,0,0},{0,0,0,0}},
 {{0,1,0,0},{0,1,1,0},{0,0,1,0},{0,0,0,0}}},

{{{1,1,0,0},{0,1,1,0},{0,0,0,0},{0,0,0,0}},
 {{0,0,1,0},{0,1,1,0},{0,1,0,0},{0,0,0,0}},
 {{1,1,0,0},{0,1,1,0},{0,0,0,0},{0,0,0,0}},
 {{0,0,1,0},{0,1,1,0},{0,1,0,0},{0,0,0,0}}}
};
int bag[7], bi = 7;
void shuffle(){
    for(int i=0;i<7;i++) bag[i]=i;
    for(int i=6;i;i--){
        int j = rand()%(i+1);
        int t=bag[i]; bag[i]=bag[j]; bag[j]=t;
    }
    bi = 0;
}
int next(){ if(bi>=7) shuffle(); return bag[bi++]; }
struct termios o;
void raw(){
    struct termios n;
    tcgetattr(0,&o);
    n=o; n.c_lflag &= ~(ICANON|ECHO);
    tcsetattr(0,TCSANOW,&n);
}
int key(){
    int c=0;
    struct timeval tv={0,0};
    fd_set f; FD_ZERO(&f); FD_SET(0,&f);
    if(select(1,&f,0,0,&tv)>0) read(0,&c,1);
    return c;
}
int p,x,y,r,lock;

int fit(int nx,int ny,int nr){
    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            if(T[p][nr][i][j]){
                int fx=nx+j, fy=ny+i;
                if(fx<0||fx>=W||fy<0||fy>=H) return 0;
                if(field[fy][fx]) return 0;
            }
    return 1;
}

int ghost(){
    int gy=y;
    while(fit(x,gy+1,r)) gy++;
    return gy;
}

void merge(){
    for(int i=0;i<4;i++)
        for(int j=0;j<4;j++)
            if(T[p][r][i][j])
                field[y+i][x+j]=p+1;
}

void clear(){
    for(int i=H-1;i>=0;i--){
        int full=1;
        for(int j=0;j<W;j++) if(!field[i][j]) full=0;
        if(full){
            score+=100;
            for(int k=i;k>0;k--)
                for(int j=0;j<W;j++)
                    field[k][j]=field[k-1][j];
            for(int j=0;j<W;j++) field[0][j]=0;
            i++;
        }
    }
}

void draw(){
    int gy = ghost();
    printf("\033[H");
    for(int i=0;i<H;i++){
        printf("|");
        for(int j=0;j<W;j++){
            int v = field[i][j];
            for(int a=0;a<4;a++)
                for(int b=0;b<4;b++)
                    if(T[p][r][a][b]){
                        if(i==y+a && j==x+b) v=p+1;
                        else if(i==gy+a && j==x+b && !v)
                            printf("::"), v=-1;
                    }
            if(v>0) printf("%s",C[v]);
            else if(v==0) printf("  ");
        }
        printf("|\n");
    }
    printf("+------------------------------+\n   Score:%d\n",score);
}

int main(){
    srand(time(0));
    raw(); shuffle();
    p=next(); x=3; y=0; r=0; lock=0;

    while(1){
        int c=key();
        if(c=='a'&&fit(x-1,y,r)) x--,lock=0;
        if(c=='d'&&fit(x+1,y,r)) x++,lock=0;
        if(c=='s'&&fit(x,y+1,r)) y++,lock=0;
        if(c=='w'&&fit(x,y,(r+1)%4)) r=(r+1)%4,lock=0;

        if(c==' '){
            y=ghost();
            merge(); clear();
            p=next(); x=3; y=0; r=0; lock=0;
            if(!fit(x,y,r)) break;
        }

        if(fit(x,y+1,r)) y++;
        else if(++lock>LOCK_DELAY){
            merge(); clear();
            p=next(); x=3; y=0; r=0; lock=0;
            if(!fit(x,y,r)) break;
        }

        draw();
        usleep(GRAVITY);
    }

    printf("\033[H\033[J \n\n GAME OVER\n Score: %d\n",score);
    return 0;
}