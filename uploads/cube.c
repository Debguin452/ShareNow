#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

#define PI 3.1415926535
#define WIDTH 150
#define HEIGHT 90

float cube[8][5] = {
	{-5, -5, -5},
	{5, -5, -5},
	{5, 5, -5},
	{-5, 5, -5},
	{-5, -5, 5},
	{5, -5, 5},
	{5, 5, 5},
	{-5, 5, 5}};

int edges[12][2] = {
	{0, 1}, {1, 2}, {2, 3}, {3, 0}, {4, 5}, {5, 6}, {6, 7}, {7, 4}, {0, 4}, {1, 5}, {2, 6}, {3, 7}};

void clear_screen()
{
	printf("\033[2J\033[1;1H");
}

void plot_point(char screen[HEIGHT][WIDTH], int x, int y)
{
	if (x >= 0 && x < WIDTH && y >= 0 && y < HEIGHT)
		screen[y][x] = '*';
}

void draw_line(char screen[HEIGHT][WIDTH], int x0, int y0, int x1, int y1)
{
	int dx = abs(x1 - x0), sx = x0 < x1 ? 1 : -1;
	int dy = -abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
	int err = dx + dy, e2;
	while (1)
	{
		plot_point(screen, x0, y0);
		if (x0 == x1 && y0 == y1)
			break;
		e2 = 2 * err;
		if (e2 >= dy)
		{
			err += dy;
			x0 += sx;
		}
		if (e2 <= dx)
		{
			err += dx;
			y0 += sy;
		}
	}
}

void print_screen(char screen[HEIGHT][WIDTH])
{
	for (int i = 0; i < HEIGHT; i++)
	{
		for (int j = 0; j < WIDTH; j++)
			putchar(screen[i][j]);
		putchar('\n');
	}
}

int main()
{
	float angle = 0;
	while (1)
	{
		char screen[HEIGHT][WIDTH];
		for (int i = 0; i < HEIGHT; i++)
			for (int j = 0; j < WIDTH; j++)
				screen[i][j] = ' ';
		float proj[8][2];
		float c = cos(angle - 5), s = sin(angle - 5);

		for (int i = 0; i < 8; i++)
		{
			float x = cube[i][0] * c - cube[i][2] * s;
			float z = cube[i][0] * s + cube[i][2] * c;
			float y = cube[i][1];

			float x2 = x;
			float y2 = y * c + z * s;
			float z2 = y * s - z * c;

			float scale = 50 / (z2 + 15);
			proj[i][0] = x2 * scale + WIDTH / 2;
			proj[i][1] = y2 * scale + HEIGHT / 2;
		}

		for (int i = 0; i < 12; i++)
		{
			int a = edges[i][0], b = edges[i][1];
			draw_line(
				screen,
				(int)proj[a][0], (int)proj[a][1],
				(int)proj[b][0], (int)proj[b][1]);
		}

		clear_screen();
		print_screen(screen);
		usleep(60000);
		angle += 0.06;
	}
	return 0;
}