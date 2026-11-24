TARGET = libyajl
DLLIB = $(TARGET).so
all:

install:
	mkdir -p /opt/gitlab/embedded/lib/ruby/gems/3.3.0/gems/libyajl2-2.1.0/lib/libyajl2/vendored-libyajl2/lib
	cp $(DLLIB) /opt/gitlab/embedded/lib/ruby/gems/3.3.0/gems/libyajl2-2.1.0/lib/libyajl2/vendored-libyajl2/lib/$(DLLIB)
	mkdir -p /opt/gitlab/embedded/lib/ruby/gems/3.3.0/gems/libyajl2-2.1.0/lib/libyajl2/vendored-libyajl2/include/yajl
	cp yajl/*.h /opt/gitlab/embedded/lib/ruby/gems/3.3.0/gems/libyajl2-2.1.0/lib/libyajl2/vendored-libyajl2/include/yajl
