# Pdfcrowd HTML to PDF API client

The Pdfcrowd API lets you easily create PDF from web pages or raw HTML
code in your Ruby applications.

## Example

    require 'pdfcrowd'
    
    begin
        # create an API client instance
        client = Pdfcrowd::Client.new("{{ username }}", "{{ apikey }}")
    
        # convert a web page and store the generated PDF into a pdf variable
        pdf = client.convertURI('http://example.com')
    
        # convert an HTML string and save the result to a file
        html="<html><body>In-memory HTML.</body></html>"
        File.open('html.pdf', 'wb') {|f| client.convertHtml(html, f)}
    
        # convert an HTML file
        File.open('file.pdf', 'wb') {|f| client.convertFile('/path/to/local/file.html', f)}
    
        # retrieve the number of tokens in your account
        ntokens = client.numTokens()
    
    rescue Pdfcrowd::Error => why
        print 'FAILED: ', why
    end

## Resources

API Home:
 <https://pdfcrowd.com/html-to-pdf-api/>
 
API Reference:
 <https://pdfcrowd.com/web-html-to-pdf-ruby/>
