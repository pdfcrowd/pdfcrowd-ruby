# Copyright (C) 2009-2011 pdfcrowd.com
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

require 'net/http'
require 'cgi'


module Pdfcrowd
  # constants for setPageLayout()
  SINGLE_PAGE, CONTINUOUS, CONTINUOUS_FACING = 1, 2, 3
  
  # constants for setPageMode()
  NONE_VISIBLE, THUMBNAILS_VISIBLE, FULLSCREEN = 1, 2, 3
  
  # constants for setInitialPdfZoomType()
  FIT_WIDTH, FIT_HEIGHT, FIT_PAGE = 1, 2, 3


  #
  # Thrown when an error occurs.
  # 
  class Error < RuntimeError
    attr_reader :http_code, :error
    
    def initialize(error, http_code=nil)
      super()
      @http_code = http_code
        @error = error
    end
    
    def to_s()

      @http_code ?  "#{@http_code} - #{@error}" : @error
    end
  end


  #
  # Pdfcrowd API client.
  # 
  class Client
    
    #
    # Client constructor.
    #
    # username -- your username at Pdfcrowd
    # apikey  -- your API key
    #
    def initialize(username, apikey)
      useSSL(false)
      @fields  = {  
        'username' => username,
        'key' => apikey,
        'html_zoom' => 200,
        'pdf_scaling_factor' => 1
      }
    end
    
    #
    # Converts a web page.
    #     
    # uri        -- a web page URL
    # outstream -- an object having method 'write(data)'; if nil then the
    #               return value is a string containing the PDF.
    #               
    def convertURI(uri, outstream=nil)
        return call_api_urlencoded('/api/pdf/convert/uri/', uri, outstream)
    end
        
    #
    # Converts an in-memory html document.
    #
    # content    -- a string containing an html document
    # outstream -- an object having method 'write(data)'; if nil then the
    #               return value is a string containing the PDF.
    # 
    def convertHtml(content, outstream=nil)
        return call_api_urlencoded('/api/pdf/convert/html/', content, outstream)
    end

    #
    # Converts an html file.
    # 
    # fpath      -- a path to an html file
    # outstream -- an object having method 'write(data)'; if nil then the
    #               return value is a string containing the PDF.
    #
    def convertFile(fpath, outstream=nil)
        return post_multipart(fpath, outstream)
    end

    #
    # Returns the number of available conversion tokens.
    # 
    def numTokens()
      uri = '/api/user/%s/tokens/' % @fields['username']
      return Integer(call_api_urlencoded(uri))
    end
    
    def useSSL(use_ssl)
        @use_ssl = use_ssl
        @api_uri = use_ssl ? HTTPS_API_URI : HTTP_API_URI
    end
    
    def setUsername(username)
        @fields['username'] = username
    end
    
    def setApiKey(key)
        @fields['key'] = key
    end
    
    def setPageWidth(value)
        @fields['width'] = value
    end
    
    def setPageHeight(value)
        @fields['height'] = value
    end
    
    def setHorizontalMargin(value)
        @fields['hmargin'] = value
    end
    
    def setVerticalMargin(value)
        @fields['vmargin'] = value
    end
    
    def setEncrypted(val=true)
        @fields['encrypted'] = val
    end
    
    def setUserPassword(pwd)
        @fields['user_pwd'] = pwd
    end
    
    def setOwnerPassword(pwd)
        @fields['owner_pwd'] = pwd
    end
    
    def setNoPrint(val=true)
        @fields['no_print'] = val
    end
    
    def setNoModify(val=true)
        @fields['no_modify'] = val
    end
    
    def setNoCopy(val=true)
        @fields['no_copy'] = val
    end
    
    def setPageLayout(value)
        assert { value > 0 and value <= 3 }
        @fields['page_layout'] = value
    end

    def setPageMode(value)
        assert { value > 0 and value <= 3 }
        @fields['page_mode'] = value
    end


    def setFooterText(value)
        @fields['footer_text'] = value
    end

    def enableImages(value=true)
        @fields['no_images'] = (not value)
    end

    def enableBackgrounds(value=true)
        @fields['no_backgrounds'] = (not value)
    end

    def setHtmlZoom(value)
        @fields['html_zoom'] = value
    end

    def enableJavaScript(value=true)
        @fields['no_javascript'] = (not value)
    end

    def enableHyperlinks(value=true)
        @fields['no_hyperlinks'] = (not value)
    end

    def setDefaultTextEncoding(value)
        @fields['text_encoding'] = value
    end

    def usePrintMedia(value=true)
        @fields['use_print_media'] = value
    end

    def setMaxPages(value)
        @fields['max_pages'] = value
    end

    def enablePdfcrowdLogo(value=true)
        @fields['pdfcrowd_logo'] = value
    end

    def setInitialPdfZoomType(value)
        assert { value>0 and value<=3 }
        @fields['initial_pdf_zoom_type'] = value
    end
    
    def setInitialPdfExactZoom(value)
        @fields['initial_pdf_zoom_type'] = 4
        @fields['initial_pdf_zoom'] = value
    end

    def setPdfScalingFactor(value)
        @fields['pdf_scaling_factor'] = value
    end

    def setFooterHtml(value)
        @fields['footer_html'] = value
    end
        
    def setFooterUrl(value)
        @fields['footer_url'] = value
    end
        
    def setHeaderHtml(value)
        @fields['header_html'] = value
    end
        
    def setHeaderUrl(value)
        @fields['header_url'] = value
    end

    def setPageBackgroundColor(value)
        @fields['page_background_color'] = value
    end

    def setTransparentBackground(value=true)
        @fields['transparent_background'] = value
    end




    # ----------------------------------------------------------------------
    #
    #                      Private stuff
    #

    private   

    def create_http_obj()
      if @use_ssl
        require 'net/https' #apt-get install libopenssl-ruby 
        http = Net::HTTP.new($api_hostname, $api_https_port)
        # OpenSSL::SSL::VERIFY_PEER fails here:
        # ... certificate verify failed ...
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.use_ssl = @use_ssl 
      else
        http = Net::HTTP.new($api_hostname, $api_http_port)
      end
      return http
    end
    
    def call_api_urlencoded(path, src=nil, out_stream=nil)
      request = Net::HTTP::Post.new(path)
      request.set_form_data(rename_post_data({'src' => src}))
      return call_api(request, out_stream)
    end
       

    def call_api(request, out_stream)
      http = create_http_obj()
      begin
        http.start {|conn|
          conn.request(request) {|response|
            case response
            when Net::HTTPSuccess
              if out_stream
                response.read_body do |chunk|
                  out_stream.write(chunk)
                end
              else
                return response.body
              end
            else
              raise Error.new(response.body, response.code)
            end
          }
        }
      rescue SystemCallError => why
        raise Error.new("#{why}\n")
      end
    end

    def rename_post_data(extra_data={})
        result = extra_data.clone()
        @fields.each { |key, val| result[key] = val if val }
        result
    end
    
    def encode_multipart_post_data(filename)
        boundary = '----------ThIs_Is_tHe_bOUnDary_$'
        body = []
        for field, value in @fields
            body << '--' + boundary << 'Content-Disposition: form-data; name="%s"' % field << '' << value.to_s if value
        end
        # filename
        body << '--' + boundary
        body << 'Content-Disposition: form-data; name="src"; filename="%s"' % filename
        mime_type = 'application/octet-stream'
        body << 'Content-Type: ' + mime_type
        body << ''
        body << open(filename).read()
        # finalize
        body << '--' + boundary + '--'
        body << ''
        body = body.join("\r\n")
        content_type = 'multipart/form-data; boundary=%s' % boundary
        return content_type, body
    end
    
    def post_multipart(fpath, out_stream)
      req = Net::HTTP::Post.new('/api/pdf/convert/html/')
      req.content_type, req.body = encode_multipart_post_data(fpath)
      return call_api(req, out_stream)
    end
end
end


def assert
  raise "Assertion failed !" unless yield
end


$api_hostname = 'pdfcrowd.com'
$api_http_port = 80
$api_https_port = 443


API_SELECTOR_BASE = '/api/'
HTTP_API_URI = "http://#{$api_hostname}#{API_SELECTOR_BASE}"
HTTPS_API_URI = "https://#{$api_hostname}#{API_SELECTOR_BASE}"



# ---------------------------------------------------------------------------
#
#                                   Test
# 

if __FILE__ == $0
  if ARGV.length < 2
    print "usage: ruby pdfcrowd.rb username apikey [hostname [http-port https-port]]\n"
    exit 1
  end

  if ARGV.length > 2
    $api_hostname=ARGV[2]
  end

  if ARGV.length == 5
    $api_http_port=ARGV[3]
    $api_https_port=ARGV[4]
  end

  print "using %s ports %d %d\n" % [$api_hostname, $api_http_port, $api_https_port]

  some_html="<html><body>Uploaded content!</body></html>"
  Dir.chdir(File.dirname($0))
  $test_dir = '../../test_files'

  def out_stream(name, use_ssl)
    fname = "#{$test_dir}/out/rb_client_#{name}"
    if use_ssl
      fname = fname + '_ssl'
    end
    return open(fname + '.pdf', 'wb')
  end

  client = Pdfcrowd::Client.new(ARGV[0], ARGV[1])
  for use_ssl in [false, true]
    client.useSSL(use_ssl)
    begin
      ntokens = client.numTokens()
      client.convertURI('http://www.jagpdf.org/', out_stream('uri', use_ssl))
      client.convertHtml(some_html, out_stream('content', use_ssl))
      client.convertFile("#{$test_dir}/in/simple.html", out_stream('upload', use_ssl))
      client.convertFile("#{$test_dir}/in/archive.tar.gz", out_stream('archive', use_ssl))
      after_tokens = client.numTokens()
      if ntokens-4 != after_tokens
        raise RuntimeError, 'got unexpected number of tokens'
      end
      print "remaining tokens: %d \n" % client.numTokens()
    rescue Pdfcrowd::Error => why
      print 'FAILED: ', why
      exit(1)
    end
  end
  # test individual methods
  begin
    for method, arg in [[:setPageWidth, 500],
                        [:setPageHeight, -1],
                        [:setHorizontalMargin, 72],
                        [:setVerticalMargin, 72],
                        [:setEncrypted, true],
                        [:setUserPassword, 'userpwd'],
                        [:setOwnerPassword, 'ownerpwd'],
                        [:setNoPrint, true],
                        [:setNoModify, true],
                        [:setNoCopy, true],
                        [:setPageLayout, Pdfcrowd::CONTINUOUS],
                        [:setPageMode, Pdfcrowd::FULLSCREEN],
                        [:setFooterText, '%p/%n | source %u'],
                        [:enableImages, false],
                        [:enableBackgrounds, false],
                        [:setHtmlZoom, 300],
                        [:enableJavaScript, false],
                        [:enableHyperlinks, false],
                        [:setDefaultTextEncoding, 'iso-8859-1'],
                        [:usePrintMedia, true],
                        [:setMaxPages, 1],
                        [:enablePdfcrowdLogo, true],
                        [:setInitialPdfZoomType, Pdfcrowd::FIT_PAGE],
                        [:setInitialPdfExactZoom, 113],
                        [:setFooterHtml, '<b>bold</b> and <i>italic</i> <img src="http://pdfcrowd.com/static/images/logo175x30.png" />'],
                        [:setFooterUrl, 'http://google.com'],
                        [:setHeaderHtml, 'page %p out of %n'],
                        [:setHeaderUrl, 'http://google.com'],
                        [:setPdfScalingFactor, 0.5],
                        [:setPageBackgroundColor, 'ee82EE'],
                        [:setTransparentBackground, true]]
      client = Pdfcrowd::Client.new(ARGV[0], ARGV[1])
      client.setVerticalMargin("1in")
      client.send(method, arg)
      client.convertFile("#{$test_dir}/in/simple.html", out_stream(method.id2name.downcase(), false))
    end
  rescue Pdfcrowd::Error => why
    print 'FAILED: ', why
    exit(1)
  end
  
end
