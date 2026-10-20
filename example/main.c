#include <stdio.h>

extern int facto(int);

int main()
{
  printf("GOOD => 6! = %d\n", facto(6));
  printf("BAD  => 0! = %d\n", facto(0));
  return 0;
}
