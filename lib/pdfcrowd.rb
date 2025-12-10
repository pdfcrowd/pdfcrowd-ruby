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
    attr_reader :http_code, :error, :message, :doc_link, :reason_code

    def initialize(error, http_code=nil)
      super()
      @error = error
      error_match = @error.match(/^(\d+)\.(\d+)\s+-\s+(.*?)(?:\s+Documentation link:\s+(.*))?$/) ||
                    @error.scan(/^(\d+)\.(\d+)\s+-\s+(.*?)(?:\s+Documentation link:\s+(.*))?$/m)
      if error_match and error_match != []
          @http_code = error_match[1]
          @reason_code = error_match[2]
          @message = error_match[3]
          @doc_link = error_match[4] || ''
      else
          @http_code = http_code
          @reason_code = -1
          @message = @error
          if @http_code
              @error = "#{@http_code} - #{@error}"
          end
          @doc_link = ''
      end
    end

    def to_s()
        @error
    end

    def getCode()
        warn "[DEPRECATION] `getCode` is obsolete and will be removed in future versions. Use `getStatusCode` instead."
        @http_code
    end

    def getStatusCode()
        @http_code
    end

    def getReasonCode()
        @reason_code
    end

    def getMessage()
        @message
    end

    def getDocumentationLink()
        @doc_link
    end
  end


  #
  # PDFCrowd API client.
  #
  class Client

    #
    # Client constructor.
    #
    # username -- your username at PDFCrowd
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
        assert_pdfcrowd { value > 0 and value <= 3 }
        @fields['page_layout'] = value
    end

    def setPageMode(value)
        assert_pdfcrowd { value > 0 and value <= 3 }
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
        assert_pdfcrowd { value>0 and value<=3 }
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


def assert_pdfcrowd
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
    CLIENT_VERSION = '6.5.4'

    class ConnectionHelper
        def initialize(user_name, api_key)
            @user_name = user_name
            @api_key = api_key

            reset_response_data()

            setProxy(nil, nil, nil, nil)
            setUseHttp(false)
            setUserAgent('pdfcrowd_ruby_client/6.5.4 (https://pdfcrowd.com)')

            @retry_count = 1
            @converter_version = '24.04'
        end

        def post(fields, files, raw_data, out_stream = nil)
            request = create_request()
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

        def setConverterVersion(converter_version)
            @converter_version = converter_version
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

        def getTotalPageCount()
            @total_page_count
        end

        def getOutputSize()
            @output_size
        end

        def getConverterVersion()
            @converter_version
        end

        private

        def reset_response_data()
            @debug_log_url = nil
            @credits = 999999
            @consumed_credits = 0
            @job_id = ''
            @page_count = 0
            @total_page_count = 0
            @output_size = 0
            @retry = 0
        end

        def create_request()
            Net::HTTP::Post.new('/convert/%s/' % @converter_version)
        end

        def self.add_file_field(name, file_name, data, body)
            body << '--' + MULTIPART_BOUNDARY
            body << 'Content-Disposition: form-data; name="%s"; filename="%s"' % [name, file_name]
            body << 'Content-Type: application/octet-stream'
            body << ''
            body << data.force_encoding('UTF-8')
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
                    if (err.getStatusCode() == '502' or err.getStatusCode() == '503') and @retry_count > @retry
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
                            @total_page_count = (response["X-Pdfcrowd-Total-Pages"] || 0).to_i
                            @output_size = (response["X-Pdfcrowd-Output-Size"] || 0).to_i

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
                    raise Error.new("400.356 - There was a problem connecting to PDFCrowd servers over HTTPS:\n#{why}" +
                                    "\nYou can still use the API over HTTP, you just need to add the following line right after PDFCrowd client initialization:\nself.setUseHttp(true)",
                                    0)
                end
            end
        end
    end

    def self.create_invalid_value_message(value, field, converter, hint, id)
        message = "400.311 - Invalid value '%s' for the '%s' option." % [value, field]
        message += " " + hint if hint
        return message + " " + "Documentation link: https://www.pdfcrowd.com/api/%s-ruby/ref/#%s" % [converter, id]
    end

# generated code

    # Conversion from HTML to PDF.
    #
    # @see https://pdfcrowd.com/api/html-to-pdf-ruby/
    class HtmlToPdfClient
        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#initialize
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

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_string
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_string_to_stream
        def convertStringToStream(text, out_stream)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_string_to_file
        def convertStringToFile(text, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStringToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_string_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "html-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_zip_main_filename
        def setZipMainFilename(filename)
            @fields['zip_main_filename'] = filename
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_size
        def setPageSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setPageSize", "html-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            end
            
            @fields['page_size'] = size
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_width
        def setPageWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setPageWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            end
            
            @fields['page_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_height
        def setPageHeight(height)
            unless /(?i)^0$|^\-1$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setPageHeight", "html-to-pdf", "The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            end
            
            @fields['page_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_dimensions
        def setPageDimensions(width, height)
            setPageWidth(width)
            setPageHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_orientation
        def setOrientation(orientation)
            unless /(?i)^(landscape|portrait)$/.match(orientation)
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_margin_top
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_margin_right
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_margin_bottom
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_margin_left
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_margins
        def setNoMargins(value)
            @fields['no_margins'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_margins
        def setPageMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_print_page_range
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*)|odd|even|last)\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*)|odd|even|last)\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "html-to-pdf", "A comma separated list of page numbers or ranges. Special strings may be used, such as 'odd', 'even' and 'last'.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_viewport_width
        def setContentViewportWidth(width)
            unless /(?i)^(balanced|small|medium|large|extra-large|[0-9]+(px)?)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setContentViewportWidth", "html-to-pdf", "The value must be 'balanced', 'small', 'medium', 'large', 'extra-large', or a number in the range 96-65000px.", "set_content_viewport_width"), 470);
            end
            
            @fields['content_viewport_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_viewport_height
        def setContentViewportHeight(height)
            unless /(?i)^(auto|large|[0-9]+(px)?)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setContentViewportHeight", "html-to-pdf", "The value must be 'auto', 'large', or a number.", "set_content_viewport_height"), 470);
            end
            
            @fields['content_viewport_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_fit_mode
        def setContentFitMode(mode)
            unless /(?i)^(auto|smart-scaling|no-scaling|viewport-width|content-width|single-page|single-page-ratio)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setContentFitMode", "html-to-pdf", "Allowed values are auto, smart-scaling, no-scaling, viewport-width, content-width, single-page, single-page-ratio.", "set_content_fit_mode"), 470);
            end
            
            @fields['content_fit_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_remove_blank_pages
        def setRemoveBlankPages(pages)
            unless /(?i)^(trailing|all|none)$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setRemoveBlankPages", "html-to-pdf", "Allowed values are trailing, all, none.", "set_remove_blank_pages"), 470);
            end
            
            @fields['remove_blank_pages'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_url
        def setHeaderUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setHeaderUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_header_url"), 470);
            end
            
            @fields['header_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_html
        def setHeaderHtml(html)
            if (!(!html.nil? && !html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(html, "setHeaderHtml", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            end
            
            @fields['header_html'] = html
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_height
        def setHeaderHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setHeaderHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_header_height"), 470);
            end
            
            @fields['header_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_zip_header_filename
        def setZipHeaderFilename(filename)
            @fields['zip_header_filename'] = filename
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_footer_url
        def setFooterUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setFooterUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_footer_url"), 470);
            end
            
            @fields['footer_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_footer_html
        def setFooterHtml(html)
            if (!(!html.nil? && !html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(html, "setFooterHtml", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            end
            
            @fields['footer_html'] = html
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_footer_height
        def setFooterHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setFooterHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_footer_height"), 470);
            end
            
            @fields['footer_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_zip_footer_filename
        def setZipFooterFilename(filename)
            @fields['zip_footer_filename'] = filename
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_header_footer_horizontal_margins
        def setNoHeaderFooterHorizontalMargins(value)
            @fields['no_header_footer_horizontal_margins'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_exclude_header_on_pages
        def setExcludeHeaderOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setExcludeHeaderOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_header_on_pages"), 470);
            end
            
            @fields['exclude_header_on_pages'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_exclude_footer_on_pages
        def setExcludeFooterOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setExcludeFooterOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            end
            
            @fields['exclude_footer_on_pages'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_footer_scale_factor
        def setHeaderFooterScaleFactor(factor)
            if (!(Integer(factor) >= 10 && Integer(factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setHeaderFooterScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_header_footer_scale_factor"), 470);
            end
            
            @fields['header_footer_scale_factor'] = factor
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_numbering_offset
        def setPageNumberingOffset(offset)
            @fields['page_numbering_offset'] = offset
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_watermark
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_watermark_url
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_multipage_watermark
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_multipage_watermark_url
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_background
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_background_url
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_multipage_background
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_multipage_background_url
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_background_color
        def setPageBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setPageBackgroundColor", "html-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            end
            
            @fields['page_background_color'] = color
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_use_print_media
        def setUsePrintMedia(value)
            @fields['use_print_media'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_background
        def setNoBackground(value)
            @fields['no_background'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_disable_javascript
        def setDisableJavascript(value)
            @fields['disable_javascript'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_disable_image_loading
        def setDisableImageLoading(value)
            @fields['disable_image_loading'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_disable_remote_fonts
        def setDisableRemoteFonts(value)
            @fields['disable_remote_fonts'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_use_mobile_user_agent
        def setUseMobileUserAgent(value)
            @fields['use_mobile_user_agent'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_load_iframes
        def setLoadIframes(iframes)
            unless /(?i)^(all|same-origin|none)$/.match(iframes)
                raise Error.new(Pdfcrowd.create_invalid_value_message(iframes, "setLoadIframes", "html-to-pdf", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            end
            
            @fields['load_iframes'] = iframes
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_block_ads
        def setBlockAds(value)
            @fields['block_ads'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_default_encoding
        def setDefaultEncoding(encoding)
            @fields['default_encoding'] = encoding
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_locale
        def setLocale(locale)
            @fields['locale'] = locale
            self
        end


        def setHttpAuthUserName(user_name)
            @fields['http_auth_user_name'] = user_name
            self
        end


        def setHttpAuthPassword(password)
            @fields['http_auth_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_http_auth
        def setHttpAuth(user_name, password)
            setHttpAuthUserName(user_name)
            setHttpAuthPassword(password)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_cookies
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_verify_ssl_certificates
        def setVerifySslCertificates(value)
            @fields['verify_ssl_certificates'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_fail_on_main_url_error
        def setFailOnMainUrlError(fail_on_error)
            @fields['fail_on_main_url_error'] = fail_on_error
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_fail_on_any_url_error
        def setFailOnAnyUrlError(fail_on_error)
            @fields['fail_on_any_url_error'] = fail_on_error
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_xpdfcrowd_header
        def setNoXpdfcrowdHeader(value)
            @fields['no_xpdfcrowd_header'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_css_page_rule_mode
        def setCssPageRuleMode(mode)
            unless /(?i)^(default|mode1|mode2)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setCssPageRuleMode", "html-to-pdf", "Allowed values are default, mode1, mode2.", "set_css_page_rule_mode"), 470);
            end
            
            @fields['css_page_rule_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_custom_css
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "html-to-pdf", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_custom_javascript
        def setCustomJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setCustomJavascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = javascript
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_on_load_javascript
        def setOnLoadJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setOnLoadJavascript", "html-to-pdf", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = javascript
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_custom_http_header
        def setCustomHttpHeader(header)
            unless /^.+:.+$/.match(header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header, "setCustomHttpHeader", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = header
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_javascript_delay
        def setJavascriptDelay(delay)
            if (!(Integer(delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(delay, "setJavascriptDelay", "html-to-pdf", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = delay
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_element_to_convert
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setElementToConvert", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_element_to_convert_mode
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setElementToConvertMode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_wait_for_element
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setWaitForElement", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_auto_detect_element_to_convert
        def setAutoDetectElementToConvert(value)
            @fields['auto_detect_element_to_convert'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_readability_enhancements
        def setReadabilityEnhancements(enhancements)
            unless /(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$/.match(enhancements)
                raise Error.new(Pdfcrowd.create_invalid_value_message(enhancements, "setReadabilityEnhancements", "html-to-pdf", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            end
            
            @fields['readability_enhancements'] = enhancements
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_viewport_width
        def setViewportWidth(width)
            if (!(Integer(width) >= 96 && Integer(width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setViewportWidth", "html-to-pdf", "The accepted range is 96-65000.", "set_viewport_width"), 470);
            end
            
            @fields['viewport_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_viewport_height
        def setViewportHeight(height)
            if (!(Integer(height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setViewportHeight", "html-to-pdf", "Must be a positive integer.", "set_viewport_height"), 470);
            end
            
            @fields['viewport_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_viewport
        def setViewport(width, height)
            setViewportWidth(width)
            setViewportHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_rendering_mode
        def setRenderingMode(mode)
            unless /(?i)^(default|viewport)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setRenderingMode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            end
            
            @fields['rendering_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_smart_scaling_mode
        def setSmartScalingMode(mode)
            unless /(?i)^(default|disabled|viewport-fit|content-fit|single-page-fit|single-page-fit-ex|mode1)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setSmartScalingMode", "html-to-pdf", "Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.", "set_smart_scaling_mode"), 470);
            end
            
            @fields['smart_scaling_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_scale_factor
        def setScaleFactor(factor)
            if (!(Integer(factor) >= 10 && Integer(factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_jpeg_quality
        def setJpegQuality(quality)
            if (!(Integer(quality) >= 1 && Integer(quality) <= 100))
                raise Error.new(Pdfcrowd.create_invalid_value_message(quality, "setJpegQuality", "html-to-pdf", "The accepted range is 1-100.", "set_jpeg_quality"), 470);
            end
            
            @fields['jpeg_quality'] = quality
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_convert_images_to_jpeg
        def setConvertImagesToJpeg(images)
            unless /(?i)^(none|opaque|all)$/.match(images)
                raise Error.new(Pdfcrowd.create_invalid_value_message(images, "setConvertImagesToJpeg", "html-to-pdf", "Allowed values are none, opaque, all.", "set_convert_images_to_jpeg"), 470);
            end
            
            @fields['convert_images_to_jpeg'] = images
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_image_dpi
        def setImageDpi(dpi)
            if (!(Integer(dpi) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(dpi, "setImageDpi", "html-to-pdf", "Must be a positive integer or 0.", "set_image_dpi"), 470);
            end
            
            @fields['image_dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_enable_pdf_forms
        def setEnablePdfForms(value)
            @fields['enable_pdf_forms'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_linearize
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_encrypt
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_user_password
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_owner_password
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_print
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_modify
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_no_copy
        def setNoCopy(value)
            @fields['no_copy'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_title
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_subject
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_author
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_keywords
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_extract_meta_tags
        def setExtractMetaTags(value)
            @fields['extract_meta_tags'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_layout
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "html-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_page_mode
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "html-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_initial_zoom_type
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "html-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_initial_page
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "html-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_initial_zoom
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "html-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_hide_toolbar
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_hide_menubar
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_hide_window_ui
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_fit_window
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_center_window
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_display_title
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_right_to_left
        def setRightToLeft(value)
            @fields['right_to_left'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_string
        def setDataString(data_string)
            @fields['data_string'] = data_string
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_file
        def setDataFile(data_file)
            @files['data_file'] = data_file
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_format
        def setDataFormat(data_format)
            unless /(?i)^(auto|json|xml|yaml|csv)$/.match(data_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "setDataFormat", "html-to-pdf", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_encoding
        def setDataEncoding(encoding)
            @fields['data_encoding'] = encoding
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_ignore_undefined
        def setDataIgnoreUndefined(value)
            @fields['data_ignore_undefined'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_auto_escape
        def setDataAutoEscape(value)
            @fields['data_auto_escape'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_trim_blocks
        def setDataTrimBlocks(value)
            @fields['data_trim_blocks'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_data_options
        def setDataOptions(options)
            @fields['data_options'] = options
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_page_count
        def getPageCount()
            return @helper.getPageCount()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_total_page_count
        def getTotalPageCount()
            return @helper.getTotalPageCount()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_client_certificate
        def setClientCertificate(certificate)
            if (!(File.file?(certificate) && !File.zero?(certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(certificate, "setClientCertificate", "html-to-pdf", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = certificate
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_client_certificate_password
        def setClientCertificatePassword(password)
            @fields['client_certificate_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_layout_dpi
        def setLayoutDpi(dpi)
            if (!(Integer(dpi) >= 72 && Integer(dpi) <= 600))
                raise Error.new(Pdfcrowd.create_invalid_value_message(dpi, "setLayoutDpi", "html-to-pdf", "The accepted range is 72-600.", "set_layout_dpi"), 470);
            end
            
            @fields['layout_dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_area_x
        def setContentAreaX(x)
            unless /(?i)^0$|^\-?[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setContentAreaX", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_x"), 470);
            end
            
            @fields['content_area_x'] = x
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_area_y
        def setContentAreaY(y)
            unless /(?i)^0$|^\-?[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setContentAreaY", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_y"), 470);
            end
            
            @fields['content_area_y'] = y
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_area_width
        def setContentAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setContentAreaWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_width"), 470);
            end
            
            @fields['content_area_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_area_height
        def setContentAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setContentAreaHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_height"), 470);
            end
            
            @fields['content_area_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_content_area
        def setContentArea(x, y, width, height)
            setContentAreaX(x)
            setContentAreaY(y)
            setContentAreaWidth(width)
            setContentAreaHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_contents_matrix
        def setContentsMatrix(matrix)
            @fields['contents_matrix'] = matrix
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_matrix
        def setHeaderMatrix(matrix)
            @fields['header_matrix'] = matrix
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_footer_matrix
        def setFooterMatrix(matrix)
            @fields['footer_matrix'] = matrix
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_disable_page_height_optimization
        def setDisablePageHeightOptimization(value)
            @fields['disable_page_height_optimization'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_main_document_css_annotation
        def setMainDocumentCssAnnotation(value)
            @fields['main_document_css_annotation'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_header_footer_css_annotation
        def setHeaderFooterCssAnnotation(value)
            @fields['header_footer_css_annotation'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_max_loading_time
        def setMaxLoadingTime(max_time)
            if (!(Integer(max_time) >= 10 && Integer(max_time) <= 30))
                raise Error.new(Pdfcrowd.create_invalid_value_message(max_time, "setMaxLoadingTime", "html-to-pdf", "The accepted range is 10-30.", "set_max_loading_time"), 470);
            end
            
            @fields['max_loading_time'] = max_time
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_conversion_config
        def setConversionConfig(json_string)
            @fields['conversion_config'] = json_string
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_conversion_config_file
        def setConversionConfigFile(filepath)
            if (!(File.file?(filepath) && !File.zero?(filepath)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(filepath, "setConversionConfigFile", "html-to-pdf", "The file must exist and not be empty.", "set_conversion_config_file"), 470);
            end
            
            @files['conversion_config_file'] = filepath
            self
        end


        def setSubprocessReferrer(referrer)
            @fields['subprocess_referrer'] = referrer
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_converter_user_agent
        def setConverterUserAgent(agent)
            @fields['converter_user_agent'] = agent
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "html-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-pdf-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from HTML to image.
    #
    # @see https://pdfcrowd.com/api/html-to-image-ruby/
    class HtmlToImageClient
        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#initialize
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

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_output_format
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "html-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "html-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "html-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "html-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_string
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertString", "html-to-image", "The string must not be empty.", "convert_string"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_string_to_stream
        def convertStringToStream(text, out_stream)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
            end
            
            @fields['text'] = text
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_string_to_file
        def convertStringToFile(text, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStringToFile::file_path", "html-to-image", "The string must not be empty.", "convert_string_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "html-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_zip_main_filename
        def setZipMainFilename(filename)
            @fields['zip_main_filename'] = filename
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_screenshot_width
        def setScreenshotWidth(width)
            if (!(Integer(width) >= 96 && Integer(width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setScreenshotWidth", "html-to-image", "The accepted range is 96-65000.", "set_screenshot_width"), 470);
            end
            
            @fields['screenshot_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_screenshot_height
        def setScreenshotHeight(height)
            if (!(Integer(height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setScreenshotHeight", "html-to-image", "Must be a positive integer.", "set_screenshot_height"), 470);
            end
            
            @fields['screenshot_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_scale_factor
        def setScaleFactor(factor)
            if (!(Integer(factor) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "html-to-image", "Must be a positive integer.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_background_color
        def setBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setBackgroundColor", "html-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_background_color"), 470);
            end
            
            @fields['background_color'] = color
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_use_print_media
        def setUsePrintMedia(value)
            @fields['use_print_media'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_no_background
        def setNoBackground(value)
            @fields['no_background'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_disable_javascript
        def setDisableJavascript(value)
            @fields['disable_javascript'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_disable_image_loading
        def setDisableImageLoading(value)
            @fields['disable_image_loading'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_disable_remote_fonts
        def setDisableRemoteFonts(value)
            @fields['disable_remote_fonts'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_use_mobile_user_agent
        def setUseMobileUserAgent(value)
            @fields['use_mobile_user_agent'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_load_iframes
        def setLoadIframes(iframes)
            unless /(?i)^(all|same-origin|none)$/.match(iframes)
                raise Error.new(Pdfcrowd.create_invalid_value_message(iframes, "setLoadIframes", "html-to-image", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            end
            
            @fields['load_iframes'] = iframes
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_block_ads
        def setBlockAds(value)
            @fields['block_ads'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_default_encoding
        def setDefaultEncoding(encoding)
            @fields['default_encoding'] = encoding
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_locale
        def setLocale(locale)
            @fields['locale'] = locale
            self
        end


        def setHttpAuthUserName(user_name)
            @fields['http_auth_user_name'] = user_name
            self
        end


        def setHttpAuthPassword(password)
            @fields['http_auth_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_http_auth
        def setHttpAuth(user_name, password)
            setHttpAuthUserName(user_name)
            setHttpAuthPassword(password)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_cookies
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_verify_ssl_certificates
        def setVerifySslCertificates(value)
            @fields['verify_ssl_certificates'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_fail_on_main_url_error
        def setFailOnMainUrlError(fail_on_error)
            @fields['fail_on_main_url_error'] = fail_on_error
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_fail_on_any_url_error
        def setFailOnAnyUrlError(fail_on_error)
            @fields['fail_on_any_url_error'] = fail_on_error
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_no_xpdfcrowd_header
        def setNoXpdfcrowdHeader(value)
            @fields['no_xpdfcrowd_header'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_custom_css
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "html-to-image", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_custom_javascript
        def setCustomJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setCustomJavascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = javascript
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_on_load_javascript
        def setOnLoadJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setOnLoadJavascript", "html-to-image", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = javascript
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_custom_http_header
        def setCustomHttpHeader(header)
            unless /^.+:.+$/.match(header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header, "setCustomHttpHeader", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = header
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_javascript_delay
        def setJavascriptDelay(delay)
            if (!(Integer(delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(delay, "setJavascriptDelay", "html-to-image", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = delay
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_element_to_convert
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setElementToConvert", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_element_to_convert_mode
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setElementToConvertMode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_wait_for_element
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setWaitForElement", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_auto_detect_element_to_convert
        def setAutoDetectElementToConvert(value)
            @fields['auto_detect_element_to_convert'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_readability_enhancements
        def setReadabilityEnhancements(enhancements)
            unless /(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$/.match(enhancements)
                raise Error.new(Pdfcrowd.create_invalid_value_message(enhancements, "setReadabilityEnhancements", "html-to-image", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            end
            
            @fields['readability_enhancements'] = enhancements
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_string
        def setDataString(data_string)
            @fields['data_string'] = data_string
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_file
        def setDataFile(data_file)
            @files['data_file'] = data_file
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_format
        def setDataFormat(data_format)
            unless /(?i)^(auto|json|xml|yaml|csv)$/.match(data_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "setDataFormat", "html-to-image", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_encoding
        def setDataEncoding(encoding)
            @fields['data_encoding'] = encoding
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_ignore_undefined
        def setDataIgnoreUndefined(value)
            @fields['data_ignore_undefined'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_auto_escape
        def setDataAutoEscape(value)
            @fields['data_auto_escape'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_trim_blocks
        def setDataTrimBlocks(value)
            @fields['data_trim_blocks'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_data_options
        def setDataOptions(options)
            @fields['data_options'] = options
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_client_certificate
        def setClientCertificate(certificate)
            if (!(File.file?(certificate) && !File.zero?(certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(certificate, "setClientCertificate", "html-to-image", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = certificate
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_client_certificate_password
        def setClientCertificatePassword(password)
            @fields['client_certificate_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_max_loading_time
        def setMaxLoadingTime(max_time)
            if (!(Integer(max_time) >= 10 && Integer(max_time) <= 30))
                raise Error.new(Pdfcrowd.create_invalid_value_message(max_time, "setMaxLoadingTime", "html-to-image", "The accepted range is 10-30.", "set_max_loading_time"), 470);
            end
            
            @fields['max_loading_time'] = max_time
            self
        end


        def setSubprocessReferrer(referrer)
            @fields['subprocess_referrer'] = referrer
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_converter_user_agent
        def setConverterUserAgent(agent)
            @fields['converter_user_agent'] = agent
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "html-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/html-to-image-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from one image format to another image format.
    #
    # @see https://pdfcrowd.com/api/image-to-image-ruby/
    class ImageToImageClient
        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#initialize
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

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "image-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "image-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "image-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "image-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_raw_data
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_raw_data_to_stream
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_raw_data_to_file
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "image-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "image-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_output_format
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_resize
        def setResize(resize)
            @fields['resize'] = resize
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_rotate
        def setRotate(rotate)
            @fields['rotate'] = rotate
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_crop_area_x
        def setCropAreaX(x)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_crop_area_y
        def setCropAreaY(y)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_crop_area_width
        def setCropAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_crop_area_height
        def setCropAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_crop_area
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_remove_borders
        def setRemoveBorders(value)
            @fields['remove_borders'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_canvas_size
        def setCanvasSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setCanvasSize", "image-to-image", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_canvas_size"), 470);
            end
            
            @fields['canvas_size'] = size
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_canvas_width
        def setCanvasWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCanvasWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_width"), 470);
            end
            
            @fields['canvas_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_canvas_height
        def setCanvasHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCanvasHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_height"), 470);
            end
            
            @fields['canvas_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_canvas_dimensions
        def setCanvasDimensions(width, height)
            setCanvasWidth(width)
            setCanvasHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_orientation
        def setOrientation(orientation)
            unless /(?i)^(landscape|portrait)$/.match(orientation)
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "image-to-image", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_position
        def setPosition(position)
            unless /(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$/.match(position)
                raise Error.new(Pdfcrowd.create_invalid_value_message(position, "setPosition", "image-to-image", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            end
            
            @fields['position'] = position
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_print_canvas_mode
        def setPrintCanvasMode(mode)
            unless /(?i)^(default|fit|stretch)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPrintCanvasMode", "image-to-image", "Allowed values are default, fit, stretch.", "set_print_canvas_mode"), 470);
            end
            
            @fields['print_canvas_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_margin_top
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_margin_right
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_margin_bottom
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_margin_left
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_margins
        def setMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_canvas_background_color
        def setCanvasBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setCanvasBackgroundColor", "image-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_canvas_background_color"), 470);
            end
            
            @fields['canvas_background_color'] = color
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_dpi
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "image-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-image-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to PDF.
    #
    # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/
    class PdfToPdfClient
        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#initialize
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

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_action
        def setAction(action)
            unless /(?i)^(join|shuffle|extract|delete)$/.match(action)
                raise Error.new(Pdfcrowd.create_invalid_value_message(action, "setAction", "pdf-to-pdf", "Allowed values are join, shuffle, extract, delete.", "set_action"), 470);
            end
            
            @fields['action'] = action
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#convert
        def convert()
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#convert_to_stream
        def convertToStream(out_stream)
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#convert_to_file
        def convertToFile(file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertToFile", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            convertToStream(output_file)
            output_file.close()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#add_pdf_file
        def addPdfFile(file_path)
            if (!(File.file?(file_path) && !File.zero?(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "addPdfFile", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            end
            
            @files['f_%s' % @file_id] = file_path
            @file_id += 1
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#add_pdf_raw_data
        def addPdfRawData(data)
            if (!(!data.nil? && data.length > 300 and data[0...4] == '%PDF'))
                raise Error.new(Pdfcrowd.create_invalid_value_message("raw PDF data", "addPdfRawData", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            end
            
            @raw_data['f_%s' % @file_id] = data
            @file_id += 1
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_input_pdf_password
        def setInputPdfPassword(password)
            @fields['input_pdf_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_range
        def setPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPageRange", "pdf-to-pdf", "A comma separated list of page numbers or ranges.", "set_page_range"), 470);
            end
            
            @fields['page_range'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_watermark
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_watermark_url
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_multipage_watermark
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_multipage_watermark_url
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_background
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_background_url
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_multipage_background
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_multipage_background_url
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_linearize
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_encrypt
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_user_password
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_owner_password
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_no_print
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_no_modify
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_no_copy
        def setNoCopy(value)
            @fields['no_copy'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_title
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_subject
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_author
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_keywords
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_use_metadata_from
        def setUseMetadataFrom(index)
            if (!(Integer(index) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(index, "setUseMetadataFrom", "pdf-to-pdf", "Must be a positive integer or 0.", "set_use_metadata_from"), 470);
            end
            
            @fields['use_metadata_from'] = index
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_layout
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "pdf-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_page_mode
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "pdf-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_initial_zoom_type
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "pdf-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_initial_page
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "pdf-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_initial_zoom
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "pdf-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_hide_toolbar
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_hide_menubar
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_hide_window_ui
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_fit_window
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_center_window
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_display_title
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_right_to_left
        def setRightToLeft(value)
            @fields['right_to_left'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_page_count
        def getPageCount()
            return @helper.getPageCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "pdf-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-pdf-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from an image to PDF.
    #
    # @see https://pdfcrowd.com/api/image-to-pdf-ruby/
    class ImageToPdfClient
        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#initialize
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

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_raw_data
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_raw_data_to_stream
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_raw_data_to_file
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_raw_data_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "image-to-pdf", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_resize
        def setResize(resize)
            @fields['resize'] = resize
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_rotate
        def setRotate(rotate)
            @fields['rotate'] = rotate
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_crop_area_x
        def setCropAreaX(x)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_crop_area_y
        def setCropAreaY(y)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_crop_area_width
        def setCropAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_crop_area_height
        def setCropAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_crop_area
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_remove_borders
        def setRemoveBorders(value)
            @fields['remove_borders'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_size
        def setPageSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setPageSize", "image-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            end
            
            @fields['page_size'] = size
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_width
        def setPageWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setPageWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            end
            
            @fields['page_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_height
        def setPageHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setPageHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            end
            
            @fields['page_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_dimensions
        def setPageDimensions(width, height)
            setPageWidth(width)
            setPageHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_orientation
        def setOrientation(orientation)
            unless /(?i)^(landscape|portrait)$/.match(orientation)
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "image-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_position
        def setPosition(position)
            unless /(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$/.match(position)
                raise Error.new(Pdfcrowd.create_invalid_value_message(position, "setPosition", "image-to-pdf", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            end
            
            @fields['position'] = position
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_print_page_mode
        def setPrintPageMode(mode)
            unless /(?i)^(default|fit|stretch)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPrintPageMode", "image-to-pdf", "Allowed values are default, fit, stretch.", "set_print_page_mode"), 470);
            end
            
            @fields['print_page_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_margin_top
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_margin_right
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_margin_bottom
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_margin_left
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_margins
        def setPageMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_background_color
        def setPageBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setPageBackgroundColor", "image-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            end
            
            @fields['page_background_color'] = color
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_dpi
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_watermark
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_watermark_url
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_multipage_watermark
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_multipage_watermark_url
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_background
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_background_url
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_multipage_background
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_multipage_background_url
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_linearize
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_encrypt
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_user_password
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_owner_password
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_no_print
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_no_modify
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_no_copy
        def setNoCopy(value)
            @fields['no_copy'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_title
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_subject
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_author
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_keywords
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_layout
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "image-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_page_mode
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "image-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_initial_zoom_type
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "image-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_initial_page
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "image-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_initial_zoom
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "image-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_hide_toolbar
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_hide_menubar
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_hide_window_ui
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_fit_window
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_center_window
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_display_title
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "image-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/image-to-pdf-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to HTML.
    #
    # @see https://pdfcrowd.com/api/pdf-to-html-ruby/
    class PdfToHtmlClient
        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#initialize
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'pdf',
                'output_format'=>'html'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_url_to_file"), 470);
            end
            
            if (!(isOutputTypeValid(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_file_to_file"), 470);
            end
            
            if (!(isOutputTypeValid(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_raw_data
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_raw_data_to_stream
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_raw_data_to_file
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_raw_data_to_file"), 470);
            end
            
            if (!(isOutputTypeValid(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_raw_data_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "pdf-to-html", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            if (!(isOutputTypeValid(file_path)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "pdf-to-html", "The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_pdf_password
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_scale_factor
        def setScaleFactor(factor)
            if (!(Integer(factor) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "pdf-to-html", "Must be a positive integer.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_print_page_range
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-html", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_dpi
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_image_mode
        def setImageMode(mode)
            unless /(?i)^(embed|separate|none)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setImageMode", "pdf-to-html", "Allowed values are embed, separate, none.", "set_image_mode"), 470);
            end
            
            @fields['image_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_image_format
        def setImageFormat(image_format)
            unless /(?i)^(png|jpg|svg)$/.match(image_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(image_format, "setImageFormat", "pdf-to-html", "Allowed values are png, jpg, svg.", "set_image_format"), 470);
            end
            
            @fields['image_format'] = image_format
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_css_mode
        def setCssMode(mode)
            unless /(?i)^(embed|separate)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setCssMode", "pdf-to-html", "Allowed values are embed, separate.", "set_css_mode"), 470);
            end
            
            @fields['css_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_font_mode
        def setFontMode(mode)
            unless /(?i)^(embed|separate)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setFontMode", "pdf-to-html", "Allowed values are embed, separate.", "set_font_mode"), 470);
            end
            
            @fields['font_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_type3_mode
        def setType3Mode(mode)
            unless /(?i)^(raster|convert)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setType3Mode", "pdf-to-html", "Allowed values are raster, convert.", "set_type3_mode"), 470);
            end
            
            @fields['type3_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_split_ligatures
        def setSplitLigatures(value)
            @fields['split_ligatures'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_custom_css
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "pdf-to-html", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_html_namespace
        def setHtmlNamespace(prefix)
            unless /(?i)^[a-z_][a-z0-9_:-]*$/.match(prefix)
                raise Error.new(Pdfcrowd.create_invalid_value_message(prefix, "setHtmlNamespace", "pdf-to-html", "Start with a letter or underscore, and use only letters, numbers, hyphens, underscores, or colons.", "set_html_namespace"), 470);
            end
            
            @fields['html_namespace'] = prefix
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#is_zipped_output
        def isZippedOutput()
            @fields.fetch('image_mode', '') == 'separate' || @fields.fetch('css_mode', '') == 'separate' || @fields.fetch('font_mode', '') == 'separate' || @fields.fetch('force_zip', false) == true
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_force_zip
        def setForceZip(value)
            @fields['force_zip'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_title
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_subject
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_author
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_keywords
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_page_count
        def getPageCount()
            return @helper.getPageCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_converter_version
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "pdf-to-html", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-html-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

        private

        def isOutputTypeValid(file_path)
            extension = File.extname(file_path).downcase
            (extension == '.zip') == isZippedOutput()
        end
    end

    # Conversion from PDF to text.
    #
    # @see https://pdfcrowd.com/api/pdf-to-text-ruby/
    class PdfToTextClient
        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#initialize
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'pdf',
                'output_format'=>'txt'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_raw_data
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_raw_data_to_stream
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_raw_data_to_file
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_raw_data_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "pdf-to-text", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_pdf_password
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_print_page_range
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-text", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_no_layout
        def setNoLayout(value)
            @fields['no_layout'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_eol
        def setEol(eol)
            unless /(?i)^(unix|dos|mac)$/.match(eol)
                raise Error.new(Pdfcrowd.create_invalid_value_message(eol, "setEol", "pdf-to-text", "Allowed values are unix, dos, mac.", "set_eol"), 470);
            end
            
            @fields['eol'] = eol
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_page_break_mode
        def setPageBreakMode(mode)
            unless /(?i)^(none|default|custom)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageBreakMode", "pdf-to-text", "Allowed values are none, default, custom.", "set_page_break_mode"), 470);
            end
            
            @fields['page_break_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_custom_page_break
        def setCustomPageBreak(page_break)
            @fields['custom_page_break'] = page_break
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_paragraph_mode
        def setParagraphMode(mode)
            unless /(?i)^(none|bounding-box|characters)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setParagraphMode", "pdf-to-text", "Allowed values are none, bounding-box, characters.", "set_paragraph_mode"), 470);
            end
            
            @fields['paragraph_mode'] = mode
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_line_spacing_threshold
        def setLineSpacingThreshold(threshold)
            unless /(?i)^0$|^[0-9]+%$/.match(threshold)
                raise Error.new(Pdfcrowd.create_invalid_value_message(threshold, "setLineSpacingThreshold", "pdf-to-text", "The value must be a positive integer percentage.", "set_line_spacing_threshold"), 470);
            end
            
            @fields['line_spacing_threshold'] = threshold
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_remove_hyphenation
        def setRemoveHyphenation(value)
            @fields['remove_hyphenation'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_remove_empty_lines
        def setRemoveEmptyLines(value)
            @fields['remove_empty_lines'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_crop_area_x
        def setCropAreaX(x)
            if (!(Integer(x) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_crop_area_y
        def setCropAreaY(y)
            if (!(Integer(y) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_crop_area_width
        def setCropAreaWidth(width)
            if (!(Integer(width) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_crop_area_height
        def setCropAreaHeight(height)
            if (!(Integer(height) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_crop_area
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_page_count
        def getPageCount()
            return @helper.getPageCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-text-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to image.
    #
    # @see https://pdfcrowd.com/api/pdf-to-image-ruby/
    class PdfToImageClient
        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#initialize
        def initialize(user_name, api_key)
            @helper = ConnectionHelper.new(user_name, api_key)
            @fields = {
                'input_format'=>'pdf',
                'output_format'=>'png'
            }
            @file_id = 1
            @files = {}
            @raw_data = {}
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_url
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_url_to_stream
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_url_to_file
        def convertUrlToFile(url, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertUrlToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_url_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_file
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_file_to_stream
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_file_to_file
        def convertFileToFile(file, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertFileToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_file_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_raw_data
        def convertRawData(data)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_raw_data_to_stream
        def convertRawDataToStream(data, out_stream)
            @raw_data['file'] = data
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_raw_data_to_file
        def convertRawDataToFile(data, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertRawDataToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_raw_data_to_file"), 470);
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

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_stream
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_stream_to_stream
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#convert_stream_to_file
        def convertStreamToFile(in_stream, file_path)
            if (!(!file_path.nil? && !file_path.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertStreamToFile::file_path", "pdf-to-image", "The string must not be empty.", "convert_stream_to_file"), 470);
            end
            
            output_file = open(file_path, "wb")
            begin
                convertStreamToStream(in_stream, output_file)
                output_file.close()
            rescue Error => why
                output_file.close()
                FileUtils.rm(file_path)
                raise
            end
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_output_format
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "pdf-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_pdf_password
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_print_page_range
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-image", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_dpi
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#is_zipped_output
        def isZippedOutput()
            @fields.fetch('force_zip', false) == true || getPageCount() > 1
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_force_zip
        def setForceZip(value)
            @fields['force_zip'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_use_cropbox
        def setUseCropbox(value)
            @fields['use_cropbox'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_crop_area_x
        def setCropAreaX(x)
            if (!(Integer(x) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_crop_area_y
        def setCropAreaY(y)
            if (!(Integer(y) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_crop_area_width
        def setCropAreaWidth(width)
            if (!(Integer(width) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_crop_area_height
        def setCropAreaHeight(height)
            if (!(Integer(height) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_crop_area
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_use_grayscale
        def setUseGrayscale(value)
            @fields['use_grayscale'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_debug_log
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_debug_log_url
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_remaining_credit_count
        def getRemainingCreditCount()
            return @helper.getRemainingCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_consumed_credit_count
        def getConsumedCreditCount()
            return @helper.getConsumedCreditCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_job_id
        def getJobId()
            return @helper.getJobId()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_page_count
        def getPageCount()
            return @helper.getPageCount()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_output_size
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#get_version
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_tag
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_http_proxy
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_https_proxy
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_use_http
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_client_user_agent
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_user_agent
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_proxy
        def setProxy(host, port, user_name, password)
            @helper.setProxy(host, port, user_name, password)
            self
        end

        # @see https://pdfcrowd.com/api/pdf-to-image-ruby/ref/#set_retry_count
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

end
