# Pdfcrowd HTML to PDF API client

The Pdfcrowd API lets you easily create PDF from web pages or raw HTML
code in your Ruby applications.

To use the API, you need an account on
[http://pdfcrowd.com](https://pdfcrowd.com), if you don't have one you
can sign up [here](https://pdfcrowd.com/pricing/api/). This will give
you a username and an API key.

## Installation

The recommended installation method is via
[RubyGems](https://rubygems.org/gems/pdfcrowd):

    sudo gem install pdfcrowd
    
Or you can build and install the gem manually:

    git clone git@github.com:pdfcrowd/pdfcrowd-ruby.git
    cd pdfcrowd-ruby/
    make gem
    sudo gem install pdfcrowd-*.gem   

## Example

    require 'pdfcrowd'
    
    begin
        # create an API client instance
        client = Pdfcrowd::Client.new("username", "apikey")
    
        # convert a web page and store the generated PDF into a pdf variable
        pdf = client.convertURI('http://example.com')
    
        # convert an HTML string and save the result to a file
        html="<html><body>In-memory HTML.</body></html>"
        File.open('html.pdf', 'wb') {|f| client.convertHtml(html, f)}
    
        # convert an HTML file
        File.open('file.pdf', 'wb') {|f| client.convertFile('/path/to/local/file.html', f)}
    
    rescue Pdfcrowd::Error => why
        print 'FAILED: ', why
    end

## Links

API Home:
 <https://pdfcrowd.com/html-to-pdf-api/>
 
API Reference:
 <https://pdfcrowd.com/web-html-to-pdf-ruby/>
