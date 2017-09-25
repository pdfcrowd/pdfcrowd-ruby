all:

dist: pdfcrowd-*.gem

gem: dist

pdfcrowd-*.gem: pdfcrowd.gemspec lib/pdfcrowd.rb
	gem build pdfcrowd.gemspec

test:
	ruby lib/pdfcrowd.rb $(API_USERNAME) $(API_TOKEN) $(API_HOSTNAME) $(API_HTTP_PORT) $(API_HTTPS_PORT)

publish: clean dist
	gem push pdfcrowd-*.gem

init:
	test -d ../test_files/out || mkdir -p ../test_files/out
	test -e test_files || ln -s ../test_files/ test_files

.PHONY: clean
clean:
	rm -rf *.gem ./test_files/out/rb_*.pdf