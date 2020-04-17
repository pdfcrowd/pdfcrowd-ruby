# Copyright (C) 2009-2018 pdfcrowd.com
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
require 'fileutils'

# ======================================
# === PDFCrowd legacy version client ===
# ======================================

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

    def getCode()
        @http_code
    end

    def getMessage()
        @error
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
    def initialize(username, apikey, hostname=nil)
      useSSL(false)
      @fields  = {
        'username' => username,
        'key' => apikey,
        'html_zoom' => 200,
        'pdf_scaling_factor' => 1
      }
      @hostname = hostname || $api_hostname;
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
        @fields['margin_right'] = @fields['margin_left'] = value.to_s()
    end

    def setVerticalMargin(value)
        @fields['margin_top'] = @fields['margin_bottom'] = value.to_s()
    end

    def setPageMargins(top, right, bottom, left)
        @fields['margin_top'] = top.to_s()
        @fields['margin_right'] = right.to_s()
        @fields['margin_bottom'] = bottom.to_s()
        @fields['margin_left'] = left.to_s()
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

    def setAuthor(value)
        @fields['author'] = value
    end

    def setFailOnNon200(value)
        @fields['fail_on_non200'] = value
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

    def setPageNumberingOffset(value)
        @fields['page_numbering_offset'] = value
    end

    def setHeaderFooterPageExcludeList(value)
        @fields['header_footer_page_exclude_list'] = value
    end

    def setWatermark(url, offset_x=0, offset_y=0)
        @fields["watermark_url"] = url
        @fields["watermark_offset_x"] = offset_x
        @fields["watermark_offset_y"] = offset_y
    end

    def setWatermarkRotation(angle)
        @fields["watermark_rotation"] = angle
    end

    def setWatermarkInBackground(val=True)
        @fields["watermark_in_background"] = val
    end



    # ----------------------------------------------------------------------
    #
    #                      Private stuff
    #

    private

    def create_http_obj()
      if @use_ssl
        require 'net/https' #apt-get install libopenssl-ruby
        http = Net::HTTP.new(@hostname, $api_https_port)
        # OpenSSL::SSL::VERIFY_PEER fails here:
        # ... certificate verify failed ...
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.use_ssl = @use_ssl
      else
        http = Net::HTTP.new(@hostname, $api_http_port)
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
        result = {}
        extra_data.each { |key, val| result[key] = val if val }
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
  $test_dir = '/tmp/legacy'
  $in_dir = File.expand_path('../../../../../../tests/input/', File.dirname(__FILE__))


  def out_stream(name, use_ssl)
    fname = $test_dir + "/out/rb_client_#{name}"
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
      client.convertURI('https://storage.googleapis.com/pdfcrowd-legacy-tests/tests/webtopdfcom.html', out_stream('uri', use_ssl))
      client.convertHtml(some_html, out_stream('content', use_ssl))
      client.convertFile("#{$in_dir}/hello_world.html", out_stream('upload', use_ssl))
      client.convertFile("#{$in_dir}/hello_world.tar.gz", out_stream('archive', use_ssl))
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
                        [:setHorizontalMargin, 0],
                        [:setEncrypted, true],
                        [:setUserPassword, 'userpwd'],
                        [:setOwnerPassword, 'ownerpwd'],
                        [:setNoPrint, true],
                        [:setNoModify, true],
                        [:setNoCopy, true],
                        [:setAuthor, "ruby test"],
                        [:setFailOnNon200, true],
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
                        [:setFooterHtml, '<b>bold</b> and <i>italic</i> <img src="http://s3.pdfcrowd.com/test-resources/logo175x30.png" />'],
                        [:setFooterUrl, 'http://s3.pdfcrowd.com/test-resources/footer.html'],
                        [:setHeaderHtml, 'page %p out of %n'],
                        [:setHeaderUrl, 'http://s3.pdfcrowd.com/test-resources/header.html'],
                        [:setPdfScalingFactor, 0.5],
                        [:setPageBackgroundColor, 'ee82EE'],
                        [:setTransparentBackground, true]]
      client = Pdfcrowd::Client.new(ARGV[0], ARGV[1])
      client.setVerticalMargin("1in")
      client.send(method, arg)
      client.convertFile("#{$in_dir}/hello_world.html", out_stream(method.id2name.downcase(), false))
    end
  rescue Pdfcrowd::Error => why
    print 'FAILED: ', why
    exit(1)
  end

  # 4 margins
  client = Pdfcrowd::Client.new(ARGV[0], ARGV[1])
  client.setPageMargins('0.25in', '0.5in', '0.75in', '1.0in')
  client.convertHtml('<div style="background-color:red;height:100%">4 margins</div>', out_stream('4margins', false))


end

# =====================================
# === PDFCrowd cloud version client ===
# =====================================

module Pdfcrowd
    HOST = ENV["PDFCROWD_HOST"] || 'api.pdfcrowd.com'
    MULTIPART_BOUNDARY = '----------ThIs_Is_tHe_bOUnDary_$'
    CLIENT_VERSION = '4.12.0'

    class ConnectionHelper
        def initialize(user_name, api_key)
            @user_name = user_name
            @api_key = api_key

            reset_response_data()

            setProxy(nil, nil, nil, nil)
            setUseHttp(false)
            setUserAgent('pdfcrowd_ruby_client/4.12.0 (http://pdfcrowd.com)')

            @retry_count = 1
        end

        def post(fields, files, raw_data, out_stream = nil)
            request = ConnectionHelper.create_request()
            request.body = ConnectionHelper.encode_multipart_post_data(fields, files, raw_data)
            request.content_type = 'multipart/form-data; boundary=' + MULTIPART_BOUNDARY
            do_post(request, out_stream)
        end

        def setUseHttp(use_http)
            @use_http = use_http
        end

        def setUserAgent(user_agent)
            @user_agent = user_agent
        end

        def setRetryCount(retry_count)
            @retry_count = retry_count
        end

        def setProxy(host, port, user_name, password)
            @proxy_host = host
            @proxy_port = port
            @proxy_user_name = user_name
            @proxy_password = password
        end

        def getDebugLogUrl()
            @debug_log_url
        end

        def getRemainingCreditCount()
            @credits
        end

        def getConsumedCreditCount()
            @consumed_credits
        end

        def getJobId()
            @job_id
        end

        def getPageCount()
            @page_count
        end

        def getOutputSize()
            @output_size
        end

        private

        def reset_response_data()
            @debug_log_url = nil
            @credits = 999999
            @consumed_credits = 0
            @job_id = ''
            @page_count = 0
            @output_size = 0
            @retry = 0
        end

        def self.create_request()
            Net::HTTP::Post.new('/convert/')
        end

        def self.add_file_field(name, file_name, data, body)
            body << '--' + MULTIPART_BOUNDARY
            body << 'Content-Disposition: form-data; name="%s"; filename="%s"' % [name, file_name]
            body << 'Content-Type: application/octet-stream'
            body << ''
            body << data
        end

        def self.encode_multipart_post_data(fields, files, raw_data)
            body = []
            for field, value in fields
                body << '--' + MULTIPART_BOUNDARY << 'Content-Disposition: form-data; name="%s"' % field << '' << value.to_s if value
            end
            for name, file_name in files
                File.open(file_name, 'rb') do |f|
                    ConnectionHelper.add_file_field(name, file_name, f.read, body)
                end
            end
            for name, data in raw_data
                ConnectionHelper.add_file_field(name, name, data, body)
            end
            # finalize
            body << '--' + MULTIPART_BOUNDARY + '--'
            body << ''
            body.join("\r\n")
        end

        def create_http_obj()
            if !@use_http
                require 'net/https' #apt-get install libopenssl-ruby
                http = Net::HTTP.new(HOST, 443)
                http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless HOST == 'api.pdfcrowd.com'
                http.use_ssl = true
            elsif @proxy_host
                http = Net::HTTP.new(HOST, 80, @proxy_host, @proxy_port, @proxy_user_name, @proxy_password)
            else
                http = Net::HTTP.new(HOST, 80)
            end

            return http
        end

        # sends a POST to the API
        def do_post(request, out_stream)
            raise Error.new("HTTPS over a proxy is not supported.") if !@use_http and @proxy_host

            reset_response_data()

            request.basic_auth(@user_name, @api_key)
            request.add_field('User-Agent', @user_agent)

            while true
                begin
                    return exec_request(request, out_stream)
                rescue Error => err
                    if err.getCode() == '502' and @retry_count > @retry
                        @retry += 1
                        sleep(@retry * 0.1)
                    else
                        raise
                    end
                end
            end
        end

        def exec_request(request, out_stream)
            begin
                http = create_http_obj()

                begin
                    http.start {|conn|
                        conn.read_timeout = 300
                        conn.request(request) {|response|
                            @debug_log_url = response["X-Pdfcrowd-Debug-Log"] || ''
                            @credits = (response["X-Pdfcrowd-Remaining-Credits"] || 999999).to_i
                            @consumed_credits = (response["X-Pdfcrowd-Consumed-Credits"] || 0).to_i
                            @job_id = response["X-Pdfcrowd-Job-Id"] || ''
                            @page_count = (response["X-Pdfcrowd-Pages"] || 0).to_i
                            @output_size = (response["X-Pdfcrowd-Output-Size"] || 0).to_i

                            raise Error.new('test 502', '502') \
                                       if ENV["PDFCROWD_UNIT_TEST_MODE"] and
                                         @retry_count > @retry

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
                rescue Timeout::Error => why
                    raise Error.new("Operation timed out\n")
                rescue OpenSSL::SSL::SSLError => why
                    raise Error.new("There was a problem connecting to Pdfcrowd servers over HTTPS:\n#{why}" +
                                    "\nYou can still use the API over HTTP, you just need to add the following line right after Pdfcrowd client initialization:\nself.setUseHttp(true)",
                                    481)
                end
            end
        end
    end

    def self.create_invalid_value_message(value, field, converter, hint, id)
        message = "Invalid value '%s' for the field '%s'." % [value, field]
        message += " " + hint if hint
        return message + " " + "Details: https://www.pdfcrowd.com/doc/api/%s/ruby/#%s" % [converter, id]
    end

# generated code

    # Conversion from HTML to PDF.
    class HtmlToPdfClient
        # Constructor for the Pdfcrowd API client.
        #
        # * +user_name+ - Your username at Pdfcrowd.
        # * +api_key+ - Your API key.
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'html',
                'output_format'=>'pdf'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # Convert a web page.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a web page and write the result to an output stream.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "html-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a web page and write the result to a local file.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertUrlToStream(url, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertFileToStream(file, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a string.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a string and write the output to an output stream.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStringToStream(text, out_stream)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a string and write the output to a file.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertStringToFile(text, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStringToStream(text, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Set the output page size.
        #
        # * +page_size+ - Allowed values are A2, A3, A4, A5, A6, Letter.
        # * *Returns* - The converter object.
        def setPageSize(page_size)
            unless /(?i)^(A2|A3|A4|A5|A6|Letter)$/.match(page_size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_size, "page_size", "html-to-pdf", "Allowed values are A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            end
            
            @fields['page_size'] = page_size
            self
        end

        # Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
        #
        # * +page_width+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setPageWidth(page_width)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(page_width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_width, "page_width", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_page_width"), 470);
            end
            
            @fields['page_width'] = page_width
            self
        end

        # Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
        #
        # * +page_height+ - Can be -1 or specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setPageHeight(page_height)
            unless /(?i)^\-1$|^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(page_height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_height, "page_height", "html-to-pdf", "Can be -1 or specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_page_height"), 470);
            end
            
            @fields['page_height'] = page_height
            self
        end

        # Set the output page dimensions.
        #
        # * +width+ - Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * +height+ - Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. Can be -1 or specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setPageDimensions(width, height)
            setPageWidth(width)
            setPageHeight(height)
            self
        end

        # Set the output page orientation.
        #
        # * +orientation+ - Allowed values are landscape, portrait.
        # * *Returns* - The converter object.
        def setOrientation(orientation)
            unless /(?i)^(landscape|portrait)$/.match(orientation)
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "orientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # Set the output page top margin.
        #
        # * +margin_top+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setMarginTop(margin_top)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(margin_top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(margin_top, "margin_top", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = margin_top
            self
        end

        # Set the output page right margin.
        #
        # * +margin_right+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setMarginRight(margin_right)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(margin_right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(margin_right, "margin_right", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = margin_right
            self
        end

        # Set the output page bottom margin.
        #
        # * +margin_bottom+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setMarginBottom(margin_bottom)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(margin_bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(margin_bottom, "margin_bottom", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = margin_bottom
            self
        end

        # Set the output page left margin.
        #
        # * +margin_left+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setMarginLeft(margin_left)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(margin_left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(margin_left, "margin_left", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = margin_left
            self
        end

        # Disable page margins.
        #
        # * +no_margins+ - Set to true to disable margins.
        # * *Returns* - The converter object.
        def setNoMargins(no_margins)
            @fields['no_margins'] = no_margins
            self
        end

        # Set the output page margins.
        #
        # * +top+ - Set the output page top margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * +right+ - Set the output page right margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * +bottom+ - Set the output page bottom margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * +left+ - Set the output page left margin. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setPageMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +header_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setHeaderUrl(header_url)
            unless /(?i)^https?:\/\/.*$/.match(header_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header_url, "header_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_header_url"), 470);
            end
            
            @fields['header_url'] = header_url
            self
        end

        # Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +header_html+ - The string must not be empty.
        # * *Returns* - The converter object.
        def setHeaderHtml(header_html)
            if (!(!header_html.nil? && !header_html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(header_html, "header_html", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            end
            
            @fields['header_html'] = header_html
            self
        end

        # Set the header height.
        #
        # * +header_height+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setHeaderHeight(header_height)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(header_height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header_height, "header_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_header_height"), 470);
            end
            
            @fields['header_height'] = header_height
            self
        end

        # Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +footer_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setFooterUrl(footer_url)
            unless /(?i)^https?:\/\/.*$/.match(footer_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(footer_url, "footer_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_footer_url"), 470);
            end
            
            @fields['footer_url'] = footer_url
            self
        end

        # Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of a converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals Arabic numerals are used by default. Roman numerals can be generated by the roman and roman-lowercase values Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL, allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +footer_html+ - The string must not be empty.
        # * *Returns* - The converter object.
        def setFooterHtml(footer_html)
            if (!(!footer_html.nil? && !footer_html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(footer_html, "footer_html", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            end
            
            @fields['footer_html'] = footer_html
            self
        end

        # Set the footer height.
        #
        # * +footer_height+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setFooterHeight(footer_height)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(footer_height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(footer_height, "footer_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_footer_height"), 470);
            end
            
            @fields['footer_height'] = footer_height
            self
        end

        # Set the page range to print.
        #
        # * +pages+ - A comma separated list of page numbers or ranges.
        # * *Returns* - The converter object.
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "pages", "html-to-pdf", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # The page header is not printed on the specified pages.
        #
        # * +pages+ - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        # * *Returns* - The converter object.
        def setExcludeHeaderOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "pages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_header_on_pages"), 470);
            end
            
            @fields['exclude_header_on_pages'] = pages
            self
        end

        # The page footer is not printed on the specified pages.
        #
        # * +pages+ - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        # * *Returns* - The converter object.
        def setExcludeFooterOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "pages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            end
            
            @fields['exclude_footer_on_pages'] = pages
            self
        end

        # Set an offset between physical and logical page numbers.
        #
        # * +offset+ - Integer specifying page offset.
        # * *Returns* - The converter object.
        def setPageNumberingOffset(offset)
            @fields['page_numbering_offset'] = offset
            self
        end

        # Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        #
        # * +content_area_x+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
        # * *Returns* - The converter object.
        def setContentAreaX(content_area_x)
            unless /(?i)^\-?[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(content_area_x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(content_area_x, "content_area_x", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.", "set_content_area_x"), 470);
            end
            
            @fields['content_area_x'] = content_area_x
            self
        end

        # Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        #
        # * +content_area_y+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
        # * *Returns* - The converter object.
        def setContentAreaY(content_area_y)
            unless /(?i)^\-?[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(content_area_y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(content_area_y, "content_area_y", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.", "set_content_area_y"), 470);
            end
            
            @fields['content_area_y'] = content_area_y
            self
        end

        # Set the width of the content area. It should be at least 1 inch.
        #
        # * +content_area_width+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setContentAreaWidth(content_area_width)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(content_area_width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(content_area_width, "content_area_width", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_content_area_width"), 470);
            end
            
            @fields['content_area_width'] = content_area_width
            self
        end

        # Set the height of the content area. It should be at least 1 inch.
        #
        # * +content_area_height+ - Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setContentAreaHeight(content_area_height)
            unless /(?i)^[0-9]*(\.[0-9]+)?(pt|px|mm|cm|in)$/.match(content_area_height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(content_area_height, "content_area_height", "html-to-pdf", "Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).", "set_content_area_height"), 470);
            end
            
            @fields['content_area_height'] = content_area_height
            self
        end

        # Set the content area position and size. The content area enables to specify a web page area to be converted.
        #
        # * +x+ - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
        # * +y+ - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt). It may contain a negative value.
        # * +width+ - Set the width of the content area. It should be at least 1 inch. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * +height+ - Set the height of the content area. It should be at least 1 inch. Can be specified in inches (in), millimeters (mm), centimeters (cm), or points (pt).
        # * *Returns* - The converter object.
        def setContentArea(x, y, width, height)
            setContentAreaX(x)
            setContentAreaY(y)
            setContentAreaWidth(width)
            setContentAreaHeight(height)
            self
        end

        # Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
        #
        # * +data_string+ - The input data string.
        # * *Returns* - The converter object.
        def setDataString(data_string)
            @fields['data_string'] = data_string
            self
        end

        # Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
        #
        # * +data_file+ - The file path to a local file containing the input data.
        # * *Returns* - The converter object.
        def setDataFile(data_file)
            @files['data_file'] = data_file
            self
        end

        # Specify the input data format.
        #
        # * +data_format+ - The data format. Allowed values are auto, json, xml, yaml, csv.
        # * *Returns* - The converter object.
        def setDataFormat(data_format)
            unless /(?i)^(auto|json|xml|yaml|csv)$/.match(data_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "data_format", "html-to-pdf", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # Set the encoding of the data file set by setDataFile.
        #
        # * +data_encoding+ - The data file encoding.
        # * *Returns* - The converter object.
        def setDataEncoding(data_encoding)
            @fields['data_encoding'] = data_encoding
            self
        end

        # Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
        #
        # * +data_ignore_undefined+ - Set to true to ignore undefined variables.
        # * *Returns* - The converter object.
        def setDataIgnoreUndefined(data_ignore_undefined)
            @fields['data_ignore_undefined'] = data_ignore_undefined
            self
        end

        # Auto escape HTML symbols in the input data before placing them into the output.
        #
        # * +data_auto_escape+ - Set to true to turn auto escaping on.
        # * *Returns* - The converter object.
        def setDataAutoEscape(data_auto_escape)
            @fields['data_auto_escape'] = data_auto_escape
            self
        end

        # Auto trim whitespace around each template command block.
        #
        # * +data_trim_blocks+ - Set to true to turn auto trimming on.
        # * *Returns* - The converter object.
        def setDataTrimBlocks(data_trim_blocks)
            @fields['data_trim_blocks'] = data_trim_blocks
            self
        end

        # Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
        #
        # * +data_options+ - Comma separated list of options.
        # * *Returns* - The converter object.
        def setDataOptions(data_options)
            @fields['data_options'] = data_options
            self
        end

        # Apply the first page of the watermark PDF to every page of the output PDF.
        #
        # * +page_watermark+ - The file path to a local watermark PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageWatermark(page_watermark)
            if (!(File.file?(page_watermark) && !File.zero?(page_watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_watermark, "page_watermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = page_watermark
            self
        end

        # Load a watermark PDF from the specified URL and apply the first page of the watermark PDF to every page of the output PDF.
        #
        # * +page_watermark_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageWatermarkUrl(page_watermark_url)
            unless /(?i)^https?:\/\/.*$/.match(page_watermark_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_watermark_url, "page_watermark_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = page_watermark_url
            self
        end

        # Apply each page of the specified watermark PDF to the corresponding page of the output PDF.
        #
        # * +multipage_watermark+ - The file path to a local watermark PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageWatermark(multipage_watermark)
            if (!(File.file?(multipage_watermark) && !File.zero?(multipage_watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_watermark, "multipage_watermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = multipage_watermark
            self
        end

        # Load a watermark PDF from the specified URL and apply each page of the specified watermark PDF to the corresponding page of the output PDF.
        #
        # * +multipage_watermark_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageWatermarkUrl(multipage_watermark_url)
            unless /(?i)^https?:\/\/.*$/.match(multipage_watermark_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_watermark_url, "multipage_watermark_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = multipage_watermark_url
            self
        end

        # Apply the first page of the specified PDF to the background of every page of the output PDF.
        #
        # * +page_background+ - The file path to a local background PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageBackground(page_background)
            if (!(File.file?(page_background) && !File.zero?(page_background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_background, "page_background", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = page_background
            self
        end

        # Load a background PDF from the specified URL and apply the first page of the background PDF to every page of the output PDF.
        #
        # * +page_background_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageBackgroundUrl(page_background_url)
            unless /(?i)^https?:\/\/.*$/.match(page_background_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_background_url, "page_background_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = page_background_url
            self
        end

        # Apply each page of the specified PDF to the background of the corresponding page of the output PDF.
        #
        # * +multipage_background+ - The file path to a local background PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageBackground(multipage_background)
            if (!(File.file?(multipage_background) && !File.zero?(multipage_background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_background, "multipage_background", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = multipage_background
            self
        end

        # Load a background PDF from the specified URL and apply each page of the specified background PDF to the corresponding page of the output PDF.
        #
        # * +multipage_background_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageBackgroundUrl(multipage_background_url)
            unless /(?i)^https?:\/\/.*$/.match(multipage_background_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_background_url, "multipage_background_url", "html-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = multipage_background_url
            self
        end

        # The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins.
        #
        # * +page_background_color+ - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        # * *Returns* - The converter object.
        def setPageBackgroundColor(page_background_color)
            unless /^[0-9a-fA-F]{6,8}$/.match(page_background_color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_background_color, "page_background_color", "html-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            end
            
            @fields['page_background_color'] = page_background_color
            self
        end

        # Do not print the background graphics.
        #
        # * +no_background+ - Set to true to disable the background graphics.
        # * *Returns* - The converter object.
        def setNoBackground(no_background)
            @fields['no_background'] = no_background
            self
        end

        # Do not execute JavaScript.
        #
        # * +disable_javascript+ - Set to true to disable JavaScript in web pages.
        # * *Returns* - The converter object.
        def setDisableJavascript(disable_javascript)
            @fields['disable_javascript'] = disable_javascript
            self
        end

        # Do not load images.
        #
        # * +disable_image_loading+ - Set to true to disable loading of images.
        # * *Returns* - The converter object.
        def setDisableImageLoading(disable_image_loading)
            @fields['disable_image_loading'] = disable_image_loading
            self
        end

        # Disable loading fonts from remote sources.
        #
        # * +disable_remote_fonts+ - Set to true disable loading remote fonts.
        # * *Returns* - The converter object.
        def setDisableRemoteFonts(disable_remote_fonts)
            @fields['disable_remote_fonts'] = disable_remote_fonts
            self
        end

        # Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        #
        # * +block_ads+ - Set to true to block ads in web pages.
        # * *Returns* - The converter object.
        def setBlockAds(block_ads)
            @fields['block_ads'] = block_ads
            self
        end

        # Set the default HTML content text encoding.
        #
        # * +default_encoding+ - The text encoding of the HTML content.
        # * *Returns* - The converter object.
        def setDefaultEncoding(default_encoding)
            @fields['default_encoding'] = default_encoding
            self
        end

        # Set the HTTP authentication user name.
        #
        # * +user_name+ - The user name.
        # * *Returns* - The converter object.
        def setHttpAuthUserName(user_name)
            @fields['http_auth_user_name'] = user_name
            self
        end

        # Set the HTTP authentication password.
        #
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setHttpAuthPassword(password)
            @fields['http_auth_password'] = password
            self
        end

        # Set credentials to access HTTP base authentication protected websites.
        #
        # * +user_name+ - Set the HTTP authentication user name.
        # * +password+ - Set the HTTP authentication password.
        # * *Returns* - The converter object.
        def setHttpAuth(user_name, password)
            setHttpAuthUserName(user_name)
            setHttpAuthPassword(password)
            self
        end

        # Use the print version of the page if available (@media print).
        #
        # * +use_print_media+ - Set to true to use the print version of the page.
        # * *Returns* - The converter object.
        def setUsePrintMedia(use_print_media)
            @fields['use_print_media'] = use_print_media
            self
        end

        # Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        #
        # * +no_xpdfcrowd_header+ - Set to true to disable sending X-Pdfcrowd HTTP header.
        # * *Returns* - The converter object.
        def setNoXpdfcrowdHeader(no_xpdfcrowd_header)
            @fields['no_xpdfcrowd_header'] = no_xpdfcrowd_header
            self
        end

        # Set cookies that are sent in Pdfcrowd HTTP requests.
        #
        # * +cookies+ - The cookie string.
        # * *Returns* - The converter object.
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # Do not allow insecure HTTPS connections.
        #
        # * +verify_ssl_certificates+ - Set to true to enable SSL certificate verification.
        # * *Returns* - The converter object.
        def setVerifySslCertificates(verify_ssl_certificates)
            @fields['verify_ssl_certificates'] = verify_ssl_certificates
            self
        end

        # Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        #
        # * +fail_on_error+ - Set to true to abort the conversion.
        # * *Returns* - The converter object.
        def setFailOnMainUrlError(fail_on_error)
            @fields['fail_on_main_url_error'] = fail_on_error
            self
        end

        # Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
        #
        # * +fail_on_error+ - Set to true to abort the conversion.
        # * *Returns* - The converter object.
        def setFailOnAnyUrlError(fail_on_error)
            @fields['fail_on_any_url_error'] = fail_on_error
            self
        end

        # Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +custom_javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomJavascript(custom_javascript)
            if (!(!custom_javascript.nil? && !custom_javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(custom_javascript, "custom_javascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = custom_javascript
            self
        end

        # Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +on_load_javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setOnLoadJavascript(on_load_javascript)
            if (!(!on_load_javascript.nil? && !on_load_javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(on_load_javascript, "on_load_javascript", "html-to-pdf", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = on_load_javascript
            self
        end

        # Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        #
        # * +custom_http_header+ - A string containing the header name and value separated by a colon.
        # * *Returns* - The converter object.
        def setCustomHttpHeader(custom_http_header)
            unless /^.+:.+$/.match(custom_http_header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(custom_http_header, "custom_http_header", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = custom_http_header
            self
        end

        # Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +javascript_delay+ - The number of milliseconds to wait. Must be a positive integer number or 0.
        # * *Returns* - The converter object.
        def setJavascriptDelay(javascript_delay)
            if (!(Integer(javascript_delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript_delay, "javascript_delay", "html-to-pdf", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = javascript_delay
            self
        end

        # Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "selectors", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # Specify the DOM handling when only a part of the document is converted.
        #
        # * +mode+ - Allowed values are cut-out, remove-siblings, hide-siblings.
        # * *Returns* - The converter object.
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "mode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "selectors", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # Set the viewport width in pixels. The viewport is the user's visible area of the page.
        #
        # * +viewport_width+ - The value must be in the range 96-65000.
        # * *Returns* - The converter object.
        def setViewportWidth(viewport_width)
            if (!(Integer(viewport_width) >= 96 && Integer(viewport_width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(viewport_width, "viewport_width", "html-to-pdf", "The value must be in the range 96-65000.", "set_viewport_width"), 470);
            end
            
            @fields['viewport_width'] = viewport_width
            self
        end

        # Set the viewport height in pixels. The viewport is the user's visible area of the page.
        #
        # * +viewport_height+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setViewportHeight(viewport_height)
            if (!(Integer(viewport_height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(viewport_height, "viewport_height", "html-to-pdf", "Must be a positive integer number.", "set_viewport_height"), 470);
            end
            
            @fields['viewport_height'] = viewport_height
            self
        end

        # Set the viewport size. The viewport is the user's visible area of the page.
        #
        # * +width+ - Set the viewport width in pixels. The viewport is the user's visible area of the page. The value must be in the range 96-65000.
        # * +height+ - Set the viewport height in pixels. The viewport is the user's visible area of the page. Must be a positive integer number.
        # * *Returns* - The converter object.
        def setViewport(width, height)
            setViewportWidth(width)
            setViewportHeight(height)
            self
        end

        # Set the rendering mode.
        #
        # * +rendering_mode+ - The rendering mode. Allowed values are default, viewport.
        # * *Returns* - The converter object.
        def setRenderingMode(rendering_mode)
            unless /(?i)^(default|viewport)$/.match(rendering_mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(rendering_mode, "rendering_mode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            end
            
            @fields['rendering_mode'] = rendering_mode
            self
        end

        # Specifies the scaling mode used for fitting the HTML contents to the print area.
        #
        # * +smart_scaling_mode+ - The smart scaling mode. Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit.
        # * *Returns* - The converter object.
        def setSmartScalingMode(smart_scaling_mode)
            unless /(?i)^(default|disabled|viewport-fit|content-fit|single-page-fit)$/.match(smart_scaling_mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(smart_scaling_mode, "smart_scaling_mode", "html-to-pdf", "Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit.", "set_smart_scaling_mode"), 470);
            end
            
            @fields['smart_scaling_mode'] = smart_scaling_mode
            self
        end

        # Set the scaling factor (zoom) for the main page area.
        #
        # * +scale_factor+ - The percentage value. The value must be in the range 10-500.
        # * *Returns* - The converter object.
        def setScaleFactor(scale_factor)
            if (!(Integer(scale_factor) >= 10 && Integer(scale_factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(scale_factor, "scale_factor", "html-to-pdf", "The value must be in the range 10-500.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = scale_factor
            self
        end

        # Set the scaling factor (zoom) for the header and footer.
        #
        # * +header_footer_scale_factor+ - The percentage value. The value must be in the range 10-500.
        # * *Returns* - The converter object.
        def setHeaderFooterScaleFactor(header_footer_scale_factor)
            if (!(Integer(header_footer_scale_factor) >= 10 && Integer(header_footer_scale_factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(header_footer_scale_factor, "header_footer_scale_factor", "html-to-pdf", "The value must be in the range 10-500.", "set_header_footer_scale_factor"), 470);
            end
            
            @fields['header_footer_scale_factor'] = header_footer_scale_factor
            self
        end

        # Disable the intelligent shrinking strategy that tries to optimally fit the HTML contents to a PDF page.
        #
        # * +disable_smart_shrinking+ - Set to true to disable the intelligent shrinking strategy.
        # * *Returns* - The converter object.
        def setDisableSmartShrinking(disable_smart_shrinking)
            @fields['disable_smart_shrinking'] = disable_smart_shrinking
            self
        end

        # Set the quality of embedded JPEG images. A lower quality results in a smaller PDF file but can lead to compression artifacts.
        #
        # * +jpeg_quality+ - The percentage value. The value must be in the range 1-100.
        # * *Returns* - The converter object.
        def setJpegQuality(jpeg_quality)
            if (!(Integer(jpeg_quality) >= 1 && Integer(jpeg_quality) <= 100))
                raise Error.new(Pdfcrowd.create_invalid_value_message(jpeg_quality, "jpeg_quality", "html-to-pdf", "The value must be in the range 1-100.", "set_jpeg_quality"), 470);
            end
            
            @fields['jpeg_quality'] = jpeg_quality
            self
        end

        # Specify which image types will be converted to JPEG. Converting lossless compression image formats (PNG, GIF, ...) to JPEG may result in a smaller PDF file.
        #
        # * +convert_images_to_jpeg+ - The image category. Allowed values are none, opaque, all.
        # * *Returns* - The converter object.
        def setConvertImagesToJpeg(convert_images_to_jpeg)
            unless /(?i)^(none|opaque|all)$/.match(convert_images_to_jpeg)
                raise Error.new(Pdfcrowd.create_invalid_value_message(convert_images_to_jpeg, "convert_images_to_jpeg", "html-to-pdf", "Allowed values are none, opaque, all.", "set_convert_images_to_jpeg"), 470);
            end
            
            @fields['convert_images_to_jpeg'] = convert_images_to_jpeg
            self
        end

        # Set the DPI of images in PDF. A lower DPI may result in a smaller PDF file. If the specified DPI is higher than the actual image DPI, the original image DPI is retained (no upscaling is performed). Use 0 to leave the images unaltered.
        #
        # * +image_dpi+ - The DPI value. Must be a positive integer number or 0.
        # * *Returns* - The converter object.
        def setImageDpi(image_dpi)
            if (!(Integer(image_dpi) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(image_dpi, "image_dpi", "html-to-pdf", "Must be a positive integer number or 0.", "set_image_dpi"), 470);
            end
            
            @fields['image_dpi'] = image_dpi
            self
        end

        # Create linearized PDF. This is also known as Fast Web View.
        #
        # * +linearize+ - Set to true to create linearized PDF.
        # * *Returns* - The converter object.
        def setLinearize(linearize)
            @fields['linearize'] = linearize
            self
        end

        # Encrypt the PDF. This prevents search engines from indexing the contents.
        #
        # * +encrypt+ - Set to true to enable PDF encryption.
        # * *Returns* - The converter object.
        def setEncrypt(encrypt)
            @fields['encrypt'] = encrypt
            self
        end

        # Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        #
        # * +user_password+ - The user password.
        # * *Returns* - The converter object.
        def setUserPassword(user_password)
            @fields['user_password'] = user_password
            self
        end

        # Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        #
        # * +owner_password+ - The owner password.
        # * *Returns* - The converter object.
        def setOwnerPassword(owner_password)
            @fields['owner_password'] = owner_password
            self
        end

        # Disallow printing of the output PDF.
        #
        # * +no_print+ - Set to true to set the no-print flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoPrint(no_print)
            @fields['no_print'] = no_print
            self
        end

        # Disallow modification of the output PDF.
        #
        # * +no_modify+ - Set to true to set the read-only only flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoModify(no_modify)
            @fields['no_modify'] = no_modify
            self
        end

        # Disallow text and graphics extraction from the output PDF.
        #
        # * +no_copy+ - Set to true to set the no-copy flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoCopy(no_copy)
            @fields['no_copy'] = no_copy
            self
        end

        # Set the title of the PDF.
        #
        # * +title+ - The title.
        # * *Returns* - The converter object.
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # Set the subject of the PDF.
        #
        # * +subject+ - The subject.
        # * *Returns* - The converter object.
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # Set the author of the PDF.
        #
        # * +author+ - The author.
        # * *Returns* - The converter object.
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # Associate keywords with the document.
        #
        # * +keywords+ - The string with the keywords.
        # * *Returns* - The converter object.
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # Specify the page layout to be used when the document is opened.
        #
        # * +page_layout+ - Allowed values are single-page, one-column, two-column-left, two-column-right.
        # * *Returns* - The converter object.
        def setPageLayout(page_layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(page_layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_layout, "page_layout", "html-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = page_layout
            self
        end

        # Specify how the document should be displayed when opened.
        #
        # * +page_mode+ - Allowed values are full-screen, thumbnails, outlines.
        # * *Returns* - The converter object.
        def setPageMode(page_mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(page_mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_mode, "page_mode", "html-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = page_mode
            self
        end

        # Specify how the page should be displayed when opened.
        #
        # * +initial_zoom_type+ - Allowed values are fit-width, fit-height, fit-page.
        # * *Returns* - The converter object.
        def setInitialZoomType(initial_zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(initial_zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_zoom_type, "initial_zoom_type", "html-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = initial_zoom_type
            self
        end

        # Display the specified page when the document is opened.
        #
        # * +initial_page+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setInitialPage(initial_page)
            if (!(Integer(initial_page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_page, "initial_page", "html-to-pdf", "Must be a positive integer number.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = initial_page
            self
        end

        # Specify the initial page zoom in percents when the document is opened.
        #
        # * +initial_zoom+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setInitialZoom(initial_zoom)
            if (!(Integer(initial_zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_zoom, "initial_zoom", "html-to-pdf", "Must be a positive integer number.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = initial_zoom
            self
        end

        # Specify whether to hide the viewer application's tool bars when the document is active.
        #
        # * +hide_toolbar+ - Set to true to hide tool bars.
        # * *Returns* - The converter object.
        def setHideToolbar(hide_toolbar)
            @fields['hide_toolbar'] = hide_toolbar
            self
        end

        # Specify whether to hide the viewer application's menu bar when the document is active.
        #
        # * +hide_menubar+ - Set to true to hide the menu bar.
        # * *Returns* - The converter object.
        def setHideMenubar(hide_menubar)
            @fields['hide_menubar'] = hide_menubar
            self
        end

        # Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        #
        # * +hide_window_ui+ - Set to true to hide ui elements.
        # * *Returns* - The converter object.
        def setHideWindowUi(hide_window_ui)
            @fields['hide_window_ui'] = hide_window_ui
            self
        end

        # Specify whether to resize the document's window to fit the size of the first displayed page.
        #
        # * +fit_window+ - Set to true to resize the window.
        # * *Returns* - The converter object.
        def setFitWindow(fit_window)
            @fields['fit_window'] = fit_window
            self
        end

        # Specify whether to position the document's window in the center of the screen.
        #
        # * +center_window+ - Set to true to center the window.
        # * *Returns* - The converter object.
        def setCenterWindow(center_window)
            @fields['center_window'] = center_window
            self
        end

        # Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        #
        # * +display_title+ - Set to true to display the title.
        # * *Returns* - The converter object.
        def setDisplayTitle(display_title)
            @fields['display_title'] = display_title
            self
        end

        # Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        #
        # * +right_to_left+ - Set to true to set right-to-left reading order.
        # * *Returns* - The converter object.
        def setRightToLeft(right_to_left)
            @fields['right_to_left'] = right_to_left
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +debug_log+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(debug_log)
            @fields['debug_log'] = debug_log
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXYZ methods.
        # The returned value can differ from the actual count if you run parallel conversions.
        # The special value 999999 is returned if the information is not available.
        # * *Returns* - The number of credits.
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # Get the number of credits consumed by the last conversion.
        # * *Returns* - The number of credits.
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # Get the job id.
        # * *Returns* - The unique job identifier.
        def getJobId()
            return @helper.getJobId()
        end

        # Get the total number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +http_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(http_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(http_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(http_proxy, "http_proxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = http_proxy
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +https_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(https_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(https_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(https_proxy, "https_proxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = https_proxy
            self
        end

        # A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        #
        # * +client_certificate+ - The file must be in PKCS12 format. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setClientCertificate(client_certificate)
            if (!(File.file?(client_certificate) && !File.zero?(client_certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(client_certificate, "client_certificate", "html-to-pdf", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = client_certificate
            self
        end

        # A password for PKCS12 file with a client certificate if it is needed.
        #
        # * +client_certificate_password+ -
        # * *Returns* - The converter object.
        def setClientCertificatePassword(client_certificate_password)
            @fields['client_certificate_password'] = client_certificate_password
            self
        end

        # Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +use_http+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(use_http)
            @helper.setUseHttp(use_http)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind some proxy or firewall.
        #
        # * +user_agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(user_agent)
            @helper.setUserAgent(user_agent)
            self
        end

        # Specifies an HTTP proxy that the API client library will use to connect to the internet.
        #
        # * +host+ - The proxy hostname.
        # * +port+ - The proxy port.
        # * +user_name+ - The username.
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +retry_count+ - Number of retries wanted.
        # * *Returns* - The converter object.
        def setRetryCount(retry_count)
            @helper.setRetryCount(retry_count)
            self
        end

    end

    # Conversion from HTML to image.
    class HtmlToImageClient
        # Constructor for the Pdfcrowd API client.
        #
        # * +user_name+ - Your username at Pdfcrowd.
        # * +api_key+ - Your API key.
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'html',
                'output_format'=>'png'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # The format of the output file.
        #
        # * +output_format+ - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        # * *Returns* - The converter object.
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "output_format", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # Convert a web page.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a web page and write the result to an output stream.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "html-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a web page and write the result to a local file.
        #
        # * +url+ - The address of the web page to convert. The supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertUrlToStream(url, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertFileToStream(file, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a string.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "text", "html-to-image", "The string must not be empty.", "convert_string"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a string and write the output to an output stream.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStringToStream(text, out_stream)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a string and write the output to a file.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertStringToFile(text, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStringToStream(text, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Set the input data for template rendering. The data format can be JSON, XML, YAML or CSV.
        #
        # * +data_string+ - The input data string.
        # * *Returns* - The converter object.
        def setDataString(data_string)
            @fields['data_string'] = data_string
            self
        end

        # Load the input data for template rendering from the specified file. The data format can be JSON, XML, YAML or CSV.
        #
        # * +data_file+ - The file path to a local file containing the input data.
        # * *Returns* - The converter object.
        def setDataFile(data_file)
            @files['data_file'] = data_file
            self
        end

        # Specify the input data format.
        #
        # * +data_format+ - The data format. Allowed values are auto, json, xml, yaml, csv.
        # * *Returns* - The converter object.
        def setDataFormat(data_format)
            unless /(?i)^(auto|json|xml|yaml|csv)$/.match(data_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "data_format", "html-to-image", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # Set the encoding of the data file set by setDataFile.
        #
        # * +data_encoding+ - The data file encoding.
        # * *Returns* - The converter object.
        def setDataEncoding(data_encoding)
            @fields['data_encoding'] = data_encoding
            self
        end

        # Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
        #
        # * +data_ignore_undefined+ - Set to true to ignore undefined variables.
        # * *Returns* - The converter object.
        def setDataIgnoreUndefined(data_ignore_undefined)
            @fields['data_ignore_undefined'] = data_ignore_undefined
            self
        end

        # Auto escape HTML symbols in the input data before placing them into the output.
        #
        # * +data_auto_escape+ - Set to true to turn auto escaping on.
        # * *Returns* - The converter object.
        def setDataAutoEscape(data_auto_escape)
            @fields['data_auto_escape'] = data_auto_escape
            self
        end

        # Auto trim whitespace around each template command block.
        #
        # * +data_trim_blocks+ - Set to true to turn auto trimming on.
        # * *Returns* - The converter object.
        def setDataTrimBlocks(data_trim_blocks)
            @fields['data_trim_blocks'] = data_trim_blocks
            self
        end

        # Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
        #
        # * +data_options+ - Comma separated list of options.
        # * *Returns* - The converter object.
        def setDataOptions(data_options)
            @fields['data_options'] = data_options
            self
        end

        # Do not print the background graphics.
        #
        # * +no_background+ - Set to true to disable the background graphics.
        # * *Returns* - The converter object.
        def setNoBackground(no_background)
            @fields['no_background'] = no_background
            self
        end

        # Do not execute JavaScript.
        #
        # * +disable_javascript+ - Set to true to disable JavaScript in web pages.
        # * *Returns* - The converter object.
        def setDisableJavascript(disable_javascript)
            @fields['disable_javascript'] = disable_javascript
            self
        end

        # Do not load images.
        #
        # * +disable_image_loading+ - Set to true to disable loading of images.
        # * *Returns* - The converter object.
        def setDisableImageLoading(disable_image_loading)
            @fields['disable_image_loading'] = disable_image_loading
            self
        end

        # Disable loading fonts from remote sources.
        #
        # * +disable_remote_fonts+ - Set to true disable loading remote fonts.
        # * *Returns* - The converter object.
        def setDisableRemoteFonts(disable_remote_fonts)
            @fields['disable_remote_fonts'] = disable_remote_fonts
            self
        end

        # Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        #
        # * +block_ads+ - Set to true to block ads in web pages.
        # * *Returns* - The converter object.
        def setBlockAds(block_ads)
            @fields['block_ads'] = block_ads
            self
        end

        # Set the default HTML content text encoding.
        #
        # * +default_encoding+ - The text encoding of the HTML content.
        # * *Returns* - The converter object.
        def setDefaultEncoding(default_encoding)
            @fields['default_encoding'] = default_encoding
            self
        end

        # Set the HTTP authentication user name.
        #
        # * +user_name+ - The user name.
        # * *Returns* - The converter object.
        def setHttpAuthUserName(user_name)
            @fields['http_auth_user_name'] = user_name
            self
        end

        # Set the HTTP authentication password.
        #
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setHttpAuthPassword(password)
            @fields['http_auth_password'] = password
            self
        end

        # Set credentials to access HTTP base authentication protected websites.
        #
        # * +user_name+ - Set the HTTP authentication user name.
        # * +password+ - Set the HTTP authentication password.
        # * *Returns* - The converter object.
        def setHttpAuth(user_name, password)
            setHttpAuthUserName(user_name)
            setHttpAuthPassword(password)
            self
        end

        # Use the print version of the page if available (@media print).
        #
        # * +use_print_media+ - Set to true to use the print version of the page.
        # * *Returns* - The converter object.
        def setUsePrintMedia(use_print_media)
            @fields['use_print_media'] = use_print_media
            self
        end

        # Do not send the X-Pdfcrowd HTTP header in Pdfcrowd HTTP requests.
        #
        # * +no_xpdfcrowd_header+ - Set to true to disable sending X-Pdfcrowd HTTP header.
        # * *Returns* - The converter object.
        def setNoXpdfcrowdHeader(no_xpdfcrowd_header)
            @fields['no_xpdfcrowd_header'] = no_xpdfcrowd_header
            self
        end

        # Set cookies that are sent in Pdfcrowd HTTP requests.
        #
        # * +cookies+ - The cookie string.
        # * *Returns* - The converter object.
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # Do not allow insecure HTTPS connections.
        #
        # * +verify_ssl_certificates+ - Set to true to enable SSL certificate verification.
        # * *Returns* - The converter object.
        def setVerifySslCertificates(verify_ssl_certificates)
            @fields['verify_ssl_certificates'] = verify_ssl_certificates
            self
        end

        # Abort the conversion if the main URL HTTP status code is greater than or equal to 400.
        #
        # * +fail_on_error+ - Set to true to abort the conversion.
        # * *Returns* - The converter object.
        def setFailOnMainUrlError(fail_on_error)
            @fields['fail_on_main_url_error'] = fail_on_error
            self
        end

        # Abort the conversion if any of the sub-request HTTP status code is greater than or equal to 400 or if some sub-requests are still pending. See details in a debug log.
        #
        # * +fail_on_error+ - Set to true to abort the conversion.
        # * *Returns* - The converter object.
        def setFailOnAnyUrlError(fail_on_error)
            @fields['fail_on_any_url_error'] = fail_on_error
            self
        end

        # Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +custom_javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomJavascript(custom_javascript)
            if (!(!custom_javascript.nil? && !custom_javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(custom_javascript, "custom_javascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = custom_javascript
            self
        end

        # Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +on_load_javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setOnLoadJavascript(on_load_javascript)
            if (!(!on_load_javascript.nil? && !on_load_javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(on_load_javascript, "on_load_javascript", "html-to-image", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = on_load_javascript
            self
        end

        # Set a custom HTTP header that is sent in Pdfcrowd HTTP requests.
        #
        # * +custom_http_header+ - A string containing the header name and value separated by a colon.
        # * *Returns* - The converter object.
        def setCustomHttpHeader(custom_http_header)
            unless /^.+:.+$/.match(custom_http_header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(custom_http_header, "custom_http_header", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = custom_http_header
            self
        end

        # Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your API license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +javascript_delay+ - The number of milliseconds to wait. Must be a positive integer number or 0.
        # * *Returns* - The converter object.
        def setJavascriptDelay(javascript_delay)
            if (!(Integer(javascript_delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript_delay, "javascript_delay", "html-to-image", "Must be a positive integer number or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = javascript_delay
            self
        end

        # Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "selectors", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # Specify the DOM handling when only a part of the document is converted.
        #
        # * +mode+ - Allowed values are cut-out, remove-siblings, hide-siblings.
        # * *Returns* - The converter object.
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "mode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your API license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "selectors", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # Set the output image width in pixels.
        #
        # * +screenshot_width+ - The value must be in the range 96-65000.
        # * *Returns* - The converter object.
        def setScreenshotWidth(screenshot_width)
            if (!(Integer(screenshot_width) >= 96 && Integer(screenshot_width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(screenshot_width, "screenshot_width", "html-to-image", "The value must be in the range 96-65000.", "set_screenshot_width"), 470);
            end
            
            @fields['screenshot_width'] = screenshot_width
            self
        end

        # Set the output image height in pixels. If it is not specified, actual document height is used.
        #
        # * +screenshot_height+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setScreenshotHeight(screenshot_height)
            if (!(Integer(screenshot_height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(screenshot_height, "screenshot_height", "html-to-image", "Must be a positive integer number.", "set_screenshot_height"), 470);
            end
            
            @fields['screenshot_height'] = screenshot_height
            self
        end

        # Set the scaling factor (zoom) for the output image.
        #
        # * +scale_factor+ - The percentage value. Must be a positive integer number.
        # * *Returns* - The converter object.
        def setScaleFactor(scale_factor)
            if (!(Integer(scale_factor) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(scale_factor, "scale_factor", "html-to-image", "Must be a positive integer number.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = scale_factor
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +debug_log+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(debug_log)
            @fields['debug_log'] = debug_log
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXYZ methods.
        # The returned value can differ from the actual count if you run parallel conversions.
        # The special value 999999 is returned if the information is not available.
        # * *Returns* - The number of credits.
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # Get the number of credits consumed by the last conversion.
        # * *Returns* - The number of credits.
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # Get the job id.
        # * *Returns* - The unique job identifier.
        def getJobId()
            return @helper.getJobId()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +http_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(http_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(http_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(http_proxy, "http_proxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = http_proxy
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +https_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(https_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(https_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(https_proxy, "https_proxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = https_proxy
            self
        end

        # A client certificate to authenticate Pdfcrowd converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        #
        # * +client_certificate+ - The file must be in PKCS12 format. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setClientCertificate(client_certificate)
            if (!(File.file?(client_certificate) && !File.zero?(client_certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(client_certificate, "client_certificate", "html-to-image", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = client_certificate
            self
        end

        # A password for PKCS12 file with a client certificate if it is needed.
        #
        # * +client_certificate_password+ -
        # * *Returns* - The converter object.
        def setClientCertificatePassword(client_certificate_password)
            @fields['client_certificate_password'] = client_certificate_password
            self
        end

        # Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +use_http+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(use_http)
            @helper.setUseHttp(use_http)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind some proxy or firewall.
        #
        # * +user_agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(user_agent)
            @helper.setUserAgent(user_agent)
            self
        end

        # Specifies an HTTP proxy that the API client library will use to connect to the internet.
        #
        # * +host+ - The proxy hostname.
        # * +port+ - The proxy port.
        # * +user_name+ - The username.
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +retry_count+ - Number of retries wanted.
        # * *Returns* - The converter object.
        def setRetryCount(retry_count)
            @helper.setRetryCount(retry_count)
            self
        end

    end

    # Conversion from one image format to another image format.
    class ImageToImageClient
        # Constructor for the Pdfcrowd API client.
        #
        # * +user_name+ - Your username at Pdfcrowd.
        # * +api_key+ - Your API key.
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'image',
                'output_format'=>'png'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # Convert an image.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert an image and write the result to an output stream.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "image-to-image", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert an image and write the result to a local file.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertUrlToStream(url, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertFileToStream(file, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert raw data.
        #
        # * +data+ - The raw content to be converted.
        # * *Returns* - Byte array with the output.
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert raw data and write the result to an output stream.
        #
        # * +data+ - The raw content to be converted.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert raw data to a file.
        #
        # * +data+ - The raw content to be converted.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertRawDataToStream(data, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # The format of the output file.
        #
        # * +output_format+ - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        # * *Returns* - The converter object.
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "output_format", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # Resize the image.
        #
        # * +resize+ - The resize percentage or new image dimensions.
        # * *Returns* - The converter object.
        def setResize(resize)
            @fields['resize'] = resize
            self
        end

        # Rotate the image.
        #
        # * +rotate+ - The rotation specified in degrees.
        # * *Returns* - The converter object.
        def setRotate(rotate)
            @fields['rotate'] = rotate
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +debug_log+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(debug_log)
            @fields['debug_log'] = debug_log
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXYZ methods.
        # The returned value can differ from the actual count if you run parallel conversions.
        # The special value 999999 is returned if the information is not available.
        # * *Returns* - The number of credits.
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # Get the number of credits consumed by the last conversion.
        # * *Returns* - The number of credits.
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # Get the job id.
        # * *Returns* - The unique job identifier.
        def getJobId()
            return @helper.getJobId()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +http_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(http_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(http_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(http_proxy, "http_proxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = http_proxy
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +https_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(https_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(https_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(https_proxy, "https_proxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = https_proxy
            self
        end

        # Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +use_http+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(use_http)
            @helper.setUseHttp(use_http)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind some proxy or firewall.
        #
        # * +user_agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(user_agent)
            @helper.setUserAgent(user_agent)
            self
        end

        # Specifies an HTTP proxy that the API client library will use to connect to the internet.
        #
        # * +host+ - The proxy hostname.
        # * +port+ - The proxy port.
        # * +user_name+ - The username.
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +retry_count+ - Number of retries wanted.
        # * *Returns* - The converter object.
        def setRetryCount(retry_count)
            @helper.setRetryCount(retry_count)
            self
        end

    end

    # Conversion from PDF to PDF.
    class PdfToPdfClient
        # Constructor for the Pdfcrowd API client.
        #
        # * +user_name+ - Your username at Pdfcrowd.
        # * +api_key+ - Your API key.
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'pdf',
                'output_format'=>'pdf'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # Specifies the action to be performed on the input PDFs.
        #
        # * +action+ - Allowed values are join, shuffle.
        # * *Returns* - The converter object.
        def setAction(action)
            unless /(?i)^(join|shuffle)$/.match(action)
                raise Error.new(Pdfcrowd.create_invalid_value_message(action, "action", "pdf-to-pdf", "Allowed values are join, shuffle.", "set_action"), 470);
            end
            
            @fields['action'] = action
            self
        end

        # Perform an action on the input files.
        # * *Returns* - Byte array containing the output PDF.
        def convert()
            @helper.post(@fields, @files, @raw_data)
        end

        # Perform an action on the input files and write the output PDF to an output stream.
        #
        # * +out_stream+ - The output stream that will contain the output PDF.
        def convertToStream(out_stream)
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Perform an action on the input files and write the output PDF to a file.
        #
        # * +file_path+ - The output file path. The string must not be empty.
        def convertToFile(file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            convertToStream(output_file)
            output_file.close()
        end

        # Add a PDF file to the list of the input PDFs.
        #
        # * +file_path+ - The file path to a local PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def addPdfFile(file_path)
            if (!(File.file?(file_path) && !File.zero?(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            end
            
            @files['f_%s' % @file_id] = file_path
            @file_id += 1
            self
        end

        # Add in-memory raw PDF data to the list of the input PDFs.Typical usage is for adding PDF created by another Pdfcrowd converter. Example in PHP: $clientPdf2Pdf->addPdfRawData($clientHtml2Pdf->convertUrl('http://www.example.com'));
        #
        # * +pdf_raw_data+ - The raw PDF data. The input data must be PDF content.
        # * *Returns* - The converter object.
        def addPdfRawData(pdf_raw_data)
            if (!(!pdf_raw_data.nil? && pdf_raw_data.length > 300 and pdf_raw_data[0...4] == '%PDF'))
                raise Error.new(Pdfcrowd.create_invalid_value_message("raw PDF data", "pdf_raw_data", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            end
            
            @raw_data['f_%s' % @file_id] = pdf_raw_data
            @file_id += 1
            self
        end

        # Apply the first page of the watermark PDF to every page of the output PDF.
        #
        # * +page_watermark+ - The file path to a local watermark PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageWatermark(page_watermark)
            if (!(File.file?(page_watermark) && !File.zero?(page_watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_watermark, "page_watermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = page_watermark
            self
        end

        # Load a watermark PDF from the specified URL and apply the first page of the watermark PDF to every page of the output PDF.
        #
        # * +page_watermark_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageWatermarkUrl(page_watermark_url)
            unless /(?i)^https?:\/\/.*$/.match(page_watermark_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_watermark_url, "page_watermark_url", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = page_watermark_url
            self
        end

        # Apply each page of the specified watermark PDF to the corresponding page of the output PDF.
        #
        # * +multipage_watermark+ - The file path to a local watermark PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageWatermark(multipage_watermark)
            if (!(File.file?(multipage_watermark) && !File.zero?(multipage_watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_watermark, "multipage_watermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = multipage_watermark
            self
        end

        # Load a watermark PDF from the specified URL and apply each page of the specified watermark PDF to the corresponding page of the output PDF.
        #
        # * +multipage_watermark_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageWatermarkUrl(multipage_watermark_url)
            unless /(?i)^https?:\/\/.*$/.match(multipage_watermark_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_watermark_url, "multipage_watermark_url", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = multipage_watermark_url
            self
        end

        # Apply the first page of the specified PDF to the background of every page of the output PDF.
        #
        # * +page_background+ - The file path to a local background PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageBackground(page_background)
            if (!(File.file?(page_background) && !File.zero?(page_background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_background, "page_background", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = page_background
            self
        end

        # Load a background PDF from the specified URL and apply the first page of the background PDF to every page of the output PDF.
        #
        # * +page_background_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageBackgroundUrl(page_background_url)
            unless /(?i)^https?:\/\/.*$/.match(page_background_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_background_url, "page_background_url", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = page_background_url
            self
        end

        # Apply each page of the specified PDF to the background of the corresponding page of the output PDF.
        #
        # * +multipage_background+ - The file path to a local background PDF file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageBackground(multipage_background)
            if (!(File.file?(multipage_background) && !File.zero?(multipage_background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_background, "multipage_background", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = multipage_background
            self
        end

        # Load a background PDF from the specified URL and apply each page of the specified background PDF to the corresponding page of the output PDF.
        #
        # * +multipage_background_url+ - The supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageBackgroundUrl(multipage_background_url)
            unless /(?i)^https?:\/\/.*$/.match(multipage_background_url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(multipage_background_url, "multipage_background_url", "pdf-to-pdf", "The supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = multipage_background_url
            self
        end

        # Create linearized PDF. This is also known as Fast Web View.
        #
        # * +linearize+ - Set to true to create linearized PDF.
        # * *Returns* - The converter object.
        def setLinearize(linearize)
            @fields['linearize'] = linearize
            self
        end

        # Encrypt the PDF. This prevents search engines from indexing the contents.
        #
        # * +encrypt+ - Set to true to enable PDF encryption.
        # * *Returns* - The converter object.
        def setEncrypt(encrypt)
            @fields['encrypt'] = encrypt
            self
        end

        # Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        #
        # * +user_password+ - The user password.
        # * *Returns* - The converter object.
        def setUserPassword(user_password)
            @fields['user_password'] = user_password
            self
        end

        # Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        #
        # * +owner_password+ - The owner password.
        # * *Returns* - The converter object.
        def setOwnerPassword(owner_password)
            @fields['owner_password'] = owner_password
            self
        end

        # Disallow printing of the output PDF.
        #
        # * +no_print+ - Set to true to set the no-print flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoPrint(no_print)
            @fields['no_print'] = no_print
            self
        end

        # Disallow modification of the output PDF.
        #
        # * +no_modify+ - Set to true to set the read-only only flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoModify(no_modify)
            @fields['no_modify'] = no_modify
            self
        end

        # Disallow text and graphics extraction from the output PDF.
        #
        # * +no_copy+ - Set to true to set the no-copy flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoCopy(no_copy)
            @fields['no_copy'] = no_copy
            self
        end

        # Specify the page layout to be used when the document is opened.
        #
        # * +page_layout+ - Allowed values are single-page, one-column, two-column-left, two-column-right.
        # * *Returns* - The converter object.
        def setPageLayout(page_layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(page_layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_layout, "page_layout", "pdf-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = page_layout
            self
        end

        # Specify how the document should be displayed when opened.
        #
        # * +page_mode+ - Allowed values are full-screen, thumbnails, outlines.
        # * *Returns* - The converter object.
        def setPageMode(page_mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(page_mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(page_mode, "page_mode", "pdf-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = page_mode
            self
        end

        # Specify how the page should be displayed when opened.
        #
        # * +initial_zoom_type+ - Allowed values are fit-width, fit-height, fit-page.
        # * *Returns* - The converter object.
        def setInitialZoomType(initial_zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(initial_zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_zoom_type, "initial_zoom_type", "pdf-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = initial_zoom_type
            self
        end

        # Display the specified page when the document is opened.
        #
        # * +initial_page+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setInitialPage(initial_page)
            if (!(Integer(initial_page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_page, "initial_page", "pdf-to-pdf", "Must be a positive integer number.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = initial_page
            self
        end

        # Specify the initial page zoom in percents when the document is opened.
        #
        # * +initial_zoom+ - Must be a positive integer number.
        # * *Returns* - The converter object.
        def setInitialZoom(initial_zoom)
            if (!(Integer(initial_zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(initial_zoom, "initial_zoom", "pdf-to-pdf", "Must be a positive integer number.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = initial_zoom
            self
        end

        # Specify whether to hide the viewer application's tool bars when the document is active.
        #
        # * +hide_toolbar+ - Set to true to hide tool bars.
        # * *Returns* - The converter object.
        def setHideToolbar(hide_toolbar)
            @fields['hide_toolbar'] = hide_toolbar
            self
        end

        # Specify whether to hide the viewer application's menu bar when the document is active.
        #
        # * +hide_menubar+ - Set to true to hide the menu bar.
        # * *Returns* - The converter object.
        def setHideMenubar(hide_menubar)
            @fields['hide_menubar'] = hide_menubar
            self
        end

        # Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        #
        # * +hide_window_ui+ - Set to true to hide ui elements.
        # * *Returns* - The converter object.
        def setHideWindowUi(hide_window_ui)
            @fields['hide_window_ui'] = hide_window_ui
            self
        end

        # Specify whether to resize the document's window to fit the size of the first displayed page.
        #
        # * +fit_window+ - Set to true to resize the window.
        # * *Returns* - The converter object.
        def setFitWindow(fit_window)
            @fields['fit_window'] = fit_window
            self
        end

        # Specify whether to position the document's window in the center of the screen.
        #
        # * +center_window+ - Set to true to center the window.
        # * *Returns* - The converter object.
        def setCenterWindow(center_window)
            @fields['center_window'] = center_window
            self
        end

        # Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        #
        # * +display_title+ - Set to true to display the title.
        # * *Returns* - The converter object.
        def setDisplayTitle(display_title)
            @fields['display_title'] = display_title
            self
        end

        # Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        #
        # * +right_to_left+ - Set to true to set right-to-left reading order.
        # * *Returns* - The converter object.
        def setRightToLeft(right_to_left)
            @fields['right_to_left'] = right_to_left
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +debug_log+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(debug_log)
            @fields['debug_log'] = debug_log
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXYZ methods.
        # The returned value can differ from the actual count if you run parallel conversions.
        # The special value 999999 is returned if the information is not available.
        # * *Returns* - The number of credits.
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # Get the number of credits consumed by the last conversion.
        # * *Returns* - The number of credits.
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # Get the job id.
        # * *Returns* - The unique job identifier.
        def getJobId()
            return @helper.getJobId()
        end

        # Get the total number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +use_http+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(use_http)
            @helper.setUseHttp(use_http)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind some proxy or firewall.
        #
        # * +user_agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(user_agent)
            @helper.setUserAgent(user_agent)
            self
        end

        # Specifies an HTTP proxy that the API client library will use to connect to the internet.
        #
        # * +host+ - The proxy hostname.
        # * +port+ - The proxy port.
        # * +user_name+ - The username.
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +retry_count+ - Number of retries wanted.
        # * *Returns* - The converter object.
        def setRetryCount(retry_count)
            @helper.setRetryCount(retry_count)
            self
        end

    end

    # Conversion from an image to PDF.
    class ImageToPdfClient
        # Constructor for the Pdfcrowd API client.
        #
        # * +user_name+ - Your username at Pdfcrowd.
        # * +api_key+ - Your API key.
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'image',
                'output_format'=>'pdf'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # Convert an image.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert an image and write the result to an output stream.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "url", "image-to-pdf", "The supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert an image and write the result to a local file.
        #
        # * +url+ - The address of the image to convert. The supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertUrlToStream(url, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertFileToStream(file, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Convert raw data.
        #
        # * +data+ - The raw content to be converted.
        # * *Returns* - Byte array with the output.
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert raw data and write the result to an output stream.
        #
        # * +data+ - The raw content to be converted.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert raw data to a file.
        #
        # * +data+ - The raw content to be converted.
        # * +file_path+ - The output file path. The string must not be empty.
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertRawDataToStream(data, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # Resize the image.
        #
        # * +resize+ - The resize percentage or new image dimensions.
        # * *Returns* - The converter object.
        def setResize(resize)
            @fields['resize'] = resize
            self
        end

        # Rotate the image.
        #
        # * +rotate+ - The rotation specified in degrees.
        # * *Returns* - The converter object.
        def setRotate(rotate)
            @fields['rotate'] = rotate
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +debug_log+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(debug_log)
            @fields['debug_log'] = debug_log
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXYZ methods.
        # The returned value can differ from the actual count if you run parallel conversions.
        # The special value 999999 is returned if the information is not available.
        # * *Returns* - The number of credits.
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # Get the number of credits consumed by the last conversion.
        # * *Returns* - The number of credits.
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # Get the job id.
        # * *Returns* - The unique job identifier.
        def getJobId()
            return @helper.getJobId()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +http_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(http_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(http_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(http_proxy, "http_proxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = http_proxy
            self
        end

        # A proxy server used by Pdfcrowd conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +https_proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(https_proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(https_proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(https_proxy, "https_proxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = https_proxy
            self
        end

        # Specifies if the client communicates over HTTP or HTTPS with Pdfcrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +use_http+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(use_http)
            @helper.setUseHttp(use_http)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind some proxy or firewall.
        #
        # * +user_agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(user_agent)
            @helper.setUserAgent(user_agent)
            self
        end

        # Specifies an HTTP proxy that the API client library will use to connect to the internet.
        #
        # * +host+ - The proxy hostname.
        # * +port+ - The proxy port.
        # * +user_name+ - The username.
        # * +password+ - The password.
        # * *Returns* - The converter object.
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # Specifies the number of retries when the 502 HTTP status code is received. The 502 status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +retry_count+ - Number of retries wanted.
        # * *Returns* - The converter object.
        def setRetryCount(retry_count)
            @helper.setRetryCount(retry_count)
            self
        end

    end

end
