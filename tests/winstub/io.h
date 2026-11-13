#ifndef WINSTUB_IO_H
#define WINSTUB_IO_H
#define _fileno(f) 1
static inline int _setmode(int fd, int mode) { (void)fd; (void)mode; return 0; }
#endif
