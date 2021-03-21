CROSS_COMPILE=

APP_TARGET=fw2b
LIBCRYPTO_TARGET=libcrypto.so
LIBCRYPTO=$(shell echo $(LIBCRYPTO_TARGET) | sed -e s/lib// -e s/.so//)

all: libcrypto app result

clean: result_clean app_clean libcrypto_clean

.PHONY: libcrypto
libcrypto:
	make TARGET=$(LIBCRYPTO_TARGET) -C libcrypto

libcrypto_clean:
	make TARGET=$(LIBCRYPTO_TARGET) clean -C libcrypto

.PHONY: app
app:
	make TARGET=$(APP_TARGET) LIBCRYPTO=$(LIBCRYPTO) -C app

app_clean:
	make TARGET=$(APP_TARGET) clean -C app

result:
	ln -sf libcrypto/$(LIBCRYPTO_TARGET) $(LIBCRYPTO_TARGET)
	ln -sf app/$(APP_TARGET) $(APP_TARGET)

result_clean:
	rm -f $(LIBCRYPTO_TARGET) $(APP_TARGET)
