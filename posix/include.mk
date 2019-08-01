PREFIX ?= /usr/local/bin

install: all
	install -Dm 0755 push $(PREFIX)/push
	install -Dm 0755 catch $(PREFIX)/catch
