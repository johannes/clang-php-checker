/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_demo.h"

#define FORMAT "lsd"

char *get_format(int a) {
  if (!a) {
    return 0;
  }
  return FORMAT;
}

int **get_location_for_int();// { return 0; }

void foo() {
  char *c;
  int i;
  long l;
  zval *z;

  zend_parse_parameters(0, "zz", &z, &i);
  zend_parse_parameters(0, "z", z);


  zend_parse_parameters(0, "sl", &c, &i, &l, &l);

  typedef char cT;
  {
    cT *cc;
    double d;
    zend_parse_parameters(0, "sdl", &cc, &i, &l, &d);
  }
  

  typedef cT* cP;
  {
    cP cc;
    zend_parse_parameters(0, "sl", &cc, &i, &l, &l);
  }

  zend_parse_parameters(0, "sl", &c, &i);

  zend_parse_parameters(0, "l", 0); // This one requires some fix ...

  zend_parse_parameters(0, "b", &l);

  zend_parse_parameters(0, "l", get_location_for_int());

  zend_parse_parameters(0, "qs", &c, &c, &i);

  extern int x;
  char *format = get_format(x);
  zend_parse_parameters(0, format, &l, &c, &i);
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
