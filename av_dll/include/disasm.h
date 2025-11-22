#ifndef DISASM_H
#define DISASM_H

#include <stdint.h>

size_t disasm_find_good_size( size_t min_size, uint8_t *code );

#endif // DISASM_H
