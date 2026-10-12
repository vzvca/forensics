main: main.c factorial.so
	$(CC) -o $@ -g3 $< factorial.so

factorial.so: factorial.c
	$(CC) -shared -g3 -o $@ $<


