all:

dist: pdfcrowd-*.gem

gem: dist

pdfcrowd-*.gem: pdfcrowd.gemspec lib/pdfcrowd.rb
	gem build pdfcrowd.gemspec

test:
	ruby lib/pdfcrowd.rb $(API_USERNAME) $(API_TOKEN) $(API_HOSTNAME) $(API_HTTP_PORT) $(API_HTTPS_PORT)

publish: clean dist
	gem push pdfcrowd-*.gem

.PHONY: clean
clean:
	rm -rf *.gem
