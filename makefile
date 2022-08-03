CXX ?= g++

DynamicDNSWatcher/usr/local/bin/dynamicdnswatcher: dynamicdnswatcher.o
	mkdir -p $(shell dirname $@)
	$(CXX) $? -o$@ -lgps

dynamicdnswatcher.o: DynamicDNSWatcher.cpp makefile
	$(CXX) -c -Wno-psabi -O3 -std=c++11 $(CXXFLAGS) $? -o$@

deb: DynamicDNSWatcher/usr/local/bin/dynamicdnswatcher DynamicDNSWatcher/DEBIAN/control DynamicDNSWatcher/usr/local/lib/systemd/system/dynamicdnswatcher.service
	# Set architecture for the resulting .deb to the actually built architecture
	sed -i "s/Architecture: .*/Architecture: $(shell dpkg --print-architecture)/" DynamicDNSWatcher/DEBIAN/control
	chmod a+x DynamicDNSWatcher/DEBIAN/postinst DynamicDNSWatcher/DEBIAN/postrm DynamicDNSWatcher/DEBIAN/prerm
	dpkg-deb --build DynamicDNSWatcher
	dpkg-name --overwrite DynamicDNSWatcher.deb

clean:
	-rm -rf DynamicDNSWatcher/usr/local/bin
	rm dynamicdnswatcher.o
	git restore DynamicDNSWatcher/DEBIAN/control

.PHONY: clean deb install-deb
