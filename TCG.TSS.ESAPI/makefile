all: esapi_getrandom esapi_create_persist_key

esapi_getrandom: esapi_getrandom.c
	gcc -o target/esapi_getrandom esapi_getrandom.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_create_persist_key: esapi_create_persist_key.c
	gcc -o target/esapi_create_persist_key esapi_create_persist_key.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include



