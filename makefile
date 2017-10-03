.PHONY: dist
dist:
	@rm -rf dist/*.gem
	@gem build pdfcrowd.gemspec
	@mkdir -p dist/
	@mv *.gem dist/

publish: clean dist
	@gem push dist/pdfcrowd-*.gem

.PHONY: clean
clean:
	@rm -rf dist/*.gem