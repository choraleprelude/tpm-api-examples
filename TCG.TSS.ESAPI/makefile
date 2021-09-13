all: esapi_getrandom esapi_create_persist_key esapi_getcap \
         esapi_delete_persistent_key esapi_rsadecrypt_persistent_key esapi_sign_persistent_key \
		 esapi_readpublic_persistent_key esapi_nvread_persistent esapi_import_persist_openssl_key

esapi_getrandom: esapi_getrandom.c
	gcc -o target/esapi_getrandom esapi_getrandom.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_create_persist_key: esapi_create_persist_key.c
	gcc -o target/esapi_create_persist_key esapi_create_persist_key.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_getcap: esapi_getcap.c
	gcc -o target/esapi_getcap esapi_getcap.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_delete_persistent_key: esapi_delete_persistent_key.c
	gcc -o target/esapi_delete_persistent_key esapi_delete_persistent_key.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_rsadecrypt_persistent_key: esapi_rsadecrypt_persistent_key.c
	gcc -o target/esapi_rsadecrypt_persistent_key esapi_rsadecrypt_persistent_key.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -I/usr/local/include

esapi_sign_persistent_key: esapi_sign_persistent_key.c
	gcc -o target/esapi_sign_persistent_key esapi_sign_persistent_key.c -L=/usr/local/lib/ -ltss2-esys -ltss2-tctildr -ltss2-mu -I/usr/local/include

esapi_readpublic_persistent_key: esapi_readpublic_persistent_key.c
	gcc -o target/esapi_readpublic_persistent_key esapi_readpublic_persistent_key.c -L=/usr/local/lib/ -L=/usr/lib/x86_64-linux-gnu/ -ltss2-esys -ltss2-tctildr -ltss2-rc -lssl -lcrypto -I/usr/local/include

esapi_nvread_persistent: esapi_nvread_persistent.c
	gcc -o target/esapi_nvread_persistent esapi_nvread_persistent.c -L=/usr/local/lib/ -L=/usr/lib/x86_64-linux-gnu/ -ltss2-esys -ltss2-tctildr -ltss2-rc -lssl -lcrypto -I/usr/local/include

esapi_import_persist_openssl_key: esapi_import_persist_openssl_key.c
	gcc -o target/esapi_import_persist_openssl_key esapi_import_persist_openssl_key.c -L=/usr/local/lib/ -L=/usr/lib/x86_64-linux-gnu/ -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-rc -lssl -lcrypto -I/usr/local/include

