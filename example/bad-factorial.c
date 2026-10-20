int facto(int n)
{
  if (n<=1)
    return n;
  else if (n > 1)
    return n*facto(n-1);
}

