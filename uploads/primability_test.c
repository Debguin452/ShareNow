#include <stdio.h>
#include <stdlib.h>
#include <time.h>
typedef long long ll;

ll mulmod(ll a, ll b, ll m)
{
	ll r = 0, x = a % m;
	while (b)
	{
		if (b & 1)
			r = (r + x) % m;
		x = (x << 1) % m;
		b >>= 1;
	}
	return r;
}
ll modexp(ll b, ll e, ll m)
{
	ll r = 1;
	while (e)
	{
		if (e & 1)
			r = mulmod(r, b, m);
		b = mulmod(b, b, m);
		e >>= 1;
	}
	return r;
}
int miller(ll d, ll n, ll a)
{
	ll x = modexp(a, d, n);
	if (x == 1 || x == n - 1)
		return 1;
	while (d != n - 1)
	{
		x = mulmod(x, x, n);
		d <<= 1;
		if (x == 1)
			return 0;
		if (x == n - 1)
			return 1;
	}
	return 0;
}
int isPrime(ll n, int k)
{
	if (n < 2 || n == 4)
		return 0;
	if (n <= 3)
		return 1;
	ll d = n - 1;
	while (!(d & 1))
		d >>= 1;
	srand(time(0));
	for (int i = 0; i < k; i++)
	{
		ll a = 2 + rand() % (n - 3);
		if (!miller(d, n, a))
			return 0;
	}
	return 1;
}
void printFactors(ll n)
{
	printf("\n  Factors of %lld :-- ", n);
	for (ll i = 1; i * i <= n; i++)
	{
		if (n % i == 0)
		{
			printf("%lld ", i);
			if (i != n / i)
				printf("%lld ", n / i);
		}
	}
	printf("\n");
}
int main()
{
	ll num;
	int k = 50;
	printf("  Enter a number: ");
	scanf("%lld", &num);
	if (isPrime(num, k))
		printf("  %lld is most probably prime.\n", num);
	else
	{
		printf("  %lld is composite.", num);
		printFactors(num);
	}
	return 0;
}