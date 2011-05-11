all:

dist: pdfcrowd-*.gem

pdfcrowd-*.gem: gemspec lib/pdfcrowd.rb
	gem build gemspec

test:
	ruby lib/pdfcrowd.rb $(API_USERNAME) $(API_TOKEN) $(API_HOSTNAME) $(API_HTTP_PORT) $(API_HTTPS_PORT)

.PHONY: clean
clean:
	rm -rf *.gem
