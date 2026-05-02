#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

double px = 8.0, py = 8.0, pa = 0.0;
double FOV = 0.9;
double MAX_D = 12;

char map[] =
"################"
"#......##......#"
"#..##..##..##..#"
"#..##........##.#"
"#......##......#"
"#..##..##..##..#"
"#..##........##.#"
"#......##......#"
"#..##..##..##..#"
"#..##........##.#"
"#......##......#"
"################";

char getKey() {
    struct termios old, new;
    char c;
    tcgetattr(0, &old);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(0, TCSANOW, &new);
    read(0, &c, 1);
    tcsetattr(0, TCSANOW, &old);
    return c;
}

void render(){
    int W = 250, H = 120;  // Fixed smaller size
    printf("\033[2J\033[H");
    
    for(int y = 0; y < H; y++){
        for(int x = 0; x < W; x++){
            double ra = (pa - FOV/2.0) + ((double)x/W)*FOV;
            double d = 0;
            int hit = 0;
            double ex = sin(ra), ey = cos(ra);
            
            while(!hit && d < MAX_D){
                d += 0.2;  // Larger steps = faster
                int tx = (int)(px + ex*d);
                int ty = (int)(py + ey*d);
                
                if(tx < 0 || tx >= 16 || ty < 0 || ty >= 12 || map[ty*16+tx] == '#'){
                    hit = 1;
                }
            }
            
            int c = H/2 - H/d;
            int f = H - c;
            
            if(y < c || y > f) putchar(' ');
            else if(d < 4) putchar('#');
            else if(d < 8) putchar('+');
            else putchar('.');
        }
        putchar('\n');
    }
}

int main() {
    render();
    
    while(1){
        char c = getKey();
        
        if(c=='a') pa -= 0.15;
        if(c=='d') pa += 0.15;
        if(c=='w'){ px += sin(pa)*0.4; py += cos(pa)*0.4; }
        if(c=='s'){ px -= sin(pa)*0.4; py -= cos(pa)*0.4; }
        if(c=='q') break;
        
        render();
    }
    return 0;
}