#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#define SIZE 3

char board[SIZE][SIZE];
void initializeBoard();
void displayBoard();
bool isMovesLeft();
int evaluate();
int minimax(int depth, bool isMax);
void findBestMove(int *row, int *col);
bool makeMove(int row, int col, char player);
bool checkWin(char player);
bool checkDraw();
void playGame();
void clearScreen();

int main()
{
	printf("=== TIC-TAC-TOE WITH AI ===\n");
	printf("You are 'X', AI is 'O'. Enter row and column (0-2).\n");
	printf("Press Enter to start...");
	getchar();
	playGame();
	return 0;
}
void clearScreen()
{
	printf("\033[H\033[J");
}
void initializeBoard()
{
	for (int i = 0; i < SIZE; i++)
	{
		for (int j = 0; j < SIZE; j++)
		{
			board[i][j] = ' ';
		}
	}
}
void displayBoard()
{
	clearScreen();
	printf("=== TIC-TAC-TOE ===\n\n");
	for (int i = 0; i < SIZE; i++)
	{
		for (int j = 0; j < SIZE; j++)
		{
			printf(" %c ", board[i][j]);
			if (j < SIZE - 1)
				printf("|");
		}
		printf("\n");
		if (i < SIZE - 1)
			printf("---|---|---\n");
	}
	printf("\n");
}
bool isMovesLeft()
{
	for (int i = 0; i < SIZE; i++)
	{
		for (int j = 0; j < SIZE; j++)
		{
			if (board[i][j] == ' ')
				return true;
		}
	}
	return false;
}
int evaluate()
{
	for (int i = 0; i < SIZE; i++)
	{
		if (board[i][0] == board[i][1] && board[i][1] == board[i][2])
		{
			if (board[i][0] == 'O')
				return 10;
			if (board[i][0] == 'X')
				return -10;
		}
		if (board[0][i] == board[1][i] && board[1][i] == board[2][i])
		{
			if (board[0][i] == 'O')
				return 10;
			if (board[0][i] == 'X')
				return -10;
		}
	}

	if (board[0][0] == board[1][1] && board[1][1] == board[2][2])
	{
		if (board[0][0] == 'O')
			return 10;
		if (board[0][0] == 'X')
			return -10;
	}

	if (board[0][2] == board[1][1] && board[1][1] == board[2][0])
	{
		if (board[0][2] == 'O')
			return 10;
		if (board[0][2] == 'X')
			return -10;
	}

	return 0;
}
int minimax(int depth, bool isMax)
{
	int score = evaluate();

	if (score == 10 || score == -10)
		return score;
	if (!isMovesLeft())
		return 0;

	if (isMax)
	{
		int best = -1000;
		for (int i = 0; i < SIZE; i++)
		{
			for (int j = 0; j < SIZE; j++)
			{
				if (board[i][j] == ' ')
				{
					board[i][j] = 'O';
					int val = minimax(depth + 1, false);
					best = (best > val) ? best : val;
					board[i][j] = ' ';
				}
			}
		}
		return best;
	}
	else
	{
		int best = 1000;
		for (int i = 0; i < SIZE; i++)
		{
			for (int j = 0; j < SIZE; j++)
			{
				if (board[i][j] == ' ')
				{
					board[i][j] = 'X';
					int val = minimax(depth + 1, true);
					best = (best < val) ? best : val;
					board[i][j] = ' ';
				}
			}
		}
		return best;
	}
}
void findBestMove(int *row, int *col)
{
	int bestVal = -1000;
	*row = -1;
	*col = -1;

	for (int i = 0; i < SIZE; i++)
	{
		for (int j = 0; j < SIZE; j++)
		{
			if (board[i][j] == ' ')
			{
				board[i][j] = 'O';
				int moveVal = minimax(0, false);
				board[i][j] = ' ';
				if (moveVal > bestVal)
				{
					bestVal = moveVal;
					*row = i;
					*col = j;
				}
			}
		}
	}
}
bool makeMove(int row, int col, char player)
{
	if (row >= 0 && row < SIZE && col >= 0 && col < SIZE && board[row][col] == ' ')
	{
		board[row][col] = player;
		return true;
	}
	return false;
}
bool checkWin(char player)
{
	for (int i = 0; i < SIZE; i++)
	{
		if (board[i][0] == player && board[i][1] == player && board[i][2] == player)
			return true;
		if (board[0][i] == player && board[1][i] == player && board[2][i] == player)
			return true;
	}
	if (board[0][0] == player && board[1][1] == player && board[2][2] == player)
		return true;
	if (board[0][2] == player && board[1][1] == player && board[2][0] == player)
		return true;
	return false;
}
bool checkDraw()
{
	return !isMovesLeft() && !checkWin('X') && !checkWin('O');
}

void playGame()
{
	initializeBoard();
	bool humanTurn = true;

	while (true)
	{
		displayBoard();

		if (humanTurn)
		{
			int row, col;
			printf("Your turn (X). Enter row and column (0-2): ");
			scanf("%d %d", &row, &col);
			if (!makeMove(row, col, 'X'))
				continue;
			if (checkWin('X'))
			{
				displayBoard();
				printf("You win!\n");
				break;
			}
		}
		else
		{
			int row, col;
			findBestMove(&row, &col);
			makeMove(row, col, 'O');
			if (checkWin('O'))
			{
				displayBoard();
				printf("AI wins!\n");
				break;
			}
		}

		if (checkDraw())
		{
			displayBoard();
			printf("It's a draw!\n");
			break;
		}

		humanTurn = !humanTurn;
	}
}