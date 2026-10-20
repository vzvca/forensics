main: main.c bad.so good.so
	$(CC) -o $@ -g3 $< bad.so

bad.so: bad-factorial.c
	$(CC) -shared -g3 -o $@ $<

good.so: good-factorial.c
	$(CC) -shared -g3 -o $@ $<


