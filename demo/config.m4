PHP_ARG_ENABLE(demo, whether to enable demo support,
[  --enable-demo           Enable demo support])

if test "$PHP_DEMO" != "no"; then
  PHP_NEW_EXTENSION(demo, demo.c, $ext_shared)
fi
