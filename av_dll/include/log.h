#ifndef LOG_H
#define LOG_H
#include <stdio.h>

#ifndef _DEBUG
#define LOG_DISABLE
#endif

#ifndef LOG_DISABLE
void log_internal_init( );
void log_internal_deinit( );
#define log_init log_internal_init
#define log_deinit log_internal_deinit
#define log( fmt, ... ) printf( fmt "\n", ##__VA_ARGS__ )
#else
#define log_init( ... )
#define log_deinit( ... )
#define log( ... )
#endif

#define log_info( fmt, ... ) log( "(*) " fmt, ##__VA_ARGS__ )
#define log_error( fmt, ... ) log( "(!) " fmt, ##__VA_ARGS__ )
#define log_ok( fmt, ... ) log( "(+) " fmt, ##__VA_ARGS__ )

#endif // LOG_H