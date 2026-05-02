#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <termios.h>
#include <sys/select.h>

#define W 50
#define H 22
#define MAX 400
#define SPEED 190000
#define RESET "\033[0m"
#define GREEN "\033[32m"
#define RED   "\033[31m"
#define CYAN  "\033[36m"
#define YELLOW "\033[33m"

int sx[MAX], sy[MAX], len=5;
int dx=1, dy=0, fx, fy, score=0;

struct termios old;
void restore(){ tcsetattr(0,TCSANOW,&old); }
void raw(){
    struct termios t;
    tcgetattr(0,&old);
    t=old; t.c_lflag&=~(ICANON|ECHO);
    tcsetattr(0,TCSANOW,&t);
    atexit(restore);
}
int key(){
    int c=0; struct timeval tv={0,0};
    fd_set f; FD_ZERO(&f); FD_SET(0,&f);
    if(select(1,&f,0,0,&tv)>0) read(0,&c,1);
    return c;
}
void food(){
    fx=rand()%(W-2)+1;
    fy=rand()%(H-2)+1;
}
void init(){
    srand(time(0));
    for(int i=0;i<len;i++){
        sx[i]=W/2-i; sy[i]=H/2;
    }
    food();
}
int hit(){
    if(sx[0]<=0||sx[0]>=W-1||sy[0]<=0||sy[0]>=H-1) return 1;
    for(int i=1;i<len;i++)
        if(sx[0]==sx[i]&&sy[0]==sy[i]) return 1;
    return 0;
}
void move(){
    for(int i=len;i>0;i--){ sx[i]=sx[i-1]; sy[i]=sy[i-1]; }
    sx[0]+=dx; sy[0]+=dy;
}
void eat(){
    if(sx[0]==fx&&sy[0]==fy){
        len++; score+=10; food();
    }
}
void draw(){
    printf("\033[H");
    for(int y=0;y<H;y++){
        for(int x=0;x<W;x++){
            if(!y||!x||y==H-1||x==W-1) printf(CYAN "#");
            else if(x==fx&&y==fy) printf(RED "@");
            else{
                int p=0;
                for(int i=0;i<len;i++)
                    if(sx[i]==x&&sy[i]==y){
                        printf(i?GREEN "o":YELLOW "O");
                        p=1; break;
                    }
                if(!p) printf(" ");
            }
        }
        printf("\n");
    }
    printf(RESET "Score: %d\n",score);
}
int main(){
    raw(); init(); printf("\033[2J");
    while(1){
        int c=key();
        if((c=='w'||c=='W')&&dy==0){dx=0;dy=-1;}
        if((c=='s'||c=='S')&&dy==0){dx=0;dy=1;}
        if((c=='a'||c=='A')&&dx==0){dx=-1;dy=0;}
        if((c=='d'||c=='D')&&dx==0){dx=1;dy=0;}
        if(c=='q'||c=='Q') break;

        move(); eat();
        if(hit()) break;
        draw();
        usleep(SPEED);
    }
    printf("\033[2J\033[HGAME OVER\nScore: %d\n",score);
    return 0;
}