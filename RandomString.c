// 2012 Colin Young
// WTFPL License
// http://sam.zoy.org/wtfpl/

#include "RandomString.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void randomString(char *str, int chars) {
    
    const char *alphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789";
    int max = strlen(alphanumeric);
    
    int i = 0;
    for (; i < chars; i++) {
        u_int32_t j = arc4random() % (max-1);
        str[i] = alphanumeric[j];
    }
    str[i+1] = '\0';
}
