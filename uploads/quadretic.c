#include <stdio.h>
#include <math.h>
#include <stdlib.h>

int gcd(int a, int b) {
	 return b ? gcd(b, a % b) : abs(a); 
	 }
void simplify(int *n, int *d)
{
	int g = gcd(*n, *d);
	*n /= g;
	*d /= g;
}
void simplify_rad(int *coef, int *rad)
{
	for (int i = 2; i * i <= *rad; i++)
		while (*rad % (i * i) == 0)
		{
			*rad /= i * i;
			*coef *= i;
		}
}
void print_frac(int n, int d)
{
	if (d == 1)
		printf("%d", n);
	else
		printf("%d/%d", n, d);
}

int main()
{
	int a, b, c;
	printf("Enter coefficients a b c(separated with space): ");
	while (scanf("%d %d %d", &a, &b, &c) == 3)
	{
		printf("\nEquation: %dx^2 + %dx + %d = 0\n\n", a, b, c);
		int D = b * b - 4 * a * c;
		double x1d, x2d;
		if (D > 0)
		{
			int rn = -b, rd = 2 * a;
			simplify(&rn, &rd);
			int rad = D, coef = 1;
			simplify_rad(&coef, &rad);
			printf("Two Real Roots:\n");
			printf("x1 = ");
			print_frac(rn, rd);
			printf(" + ");
			if (coef != 1)
				printf("%d", coef);
			printf("√%d", rad);
			x1d = (-b + sqrt(D)) / (2.0 * a);
			printf("  (%.5f)\n", x1d);
			printf("x2 = ");
			print_frac(rn, rd);
			printf(" - ");
			if (coef != 1)
				printf("%d", coef);
			printf("√%d", rad);
			x2d = (-b - sqrt(D)) / (2.0 * a);
			printf("  (%.5f)\n", x2d);
		}
		else if (D == 0)
		{
			int n = -b, d = 2 * a;
			simplify(&n, &d);
			double xd = -b / (2.0 * a);
			printf("One Real Root:\n");
			printf("x = ");
			print_frac(n, d);
			printf("  (%.5f)\n", xd);
		}
		else
		{
			int rn = -b, rd = 2 * a;
			simplify(&rn, &rd);
			int rad = -D, coef = 1;
			simplify_rad(&coef, &rad);
			double real = -b / (2.0 * a), imag = sqrt(-D) / (2.0 * a);
			printf("Two Imaginary Roots:\n");
			printf("x1 = ");
			print_frac(rn, rd);
			printf(" + ");
			if (coef != 1)
				printf("%d", coef);
			printf("√%di  (%.5f + %.5fi)\n", rad, real, imag);
			printf("x2 = ");
			print_frac(rn, rd);
			printf(" - ");
			if (coef != 1)
				printf("%d", coef);
			printf("√%di  (%.5f - %.5fi)\n", rad, real, imag);
			}
		}
	}