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
    CLIENT_VERSION = '6.5.2'

    class ConnectionHelper
        def initialize(user_name, api_key)
            @user_name = user_name
            @api_key = api_key

            reset_response_data()

            setProxy(nil, nil, nil, nil)
            setUseHttp(false)
            setUserAgent('pdfcrowd_ruby_client/6.5.2 (https://pdfcrowd.com)')

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
    class HtmlToPdfClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
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
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a web page and write the result to an output stream.
        #
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "html-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a web page and write the result to a local file.
        #
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "html-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "html-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
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

        # Convert a string.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertString", "html-to-pdf", "The string must not be empty.", "convert_string"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertStringToStream::text", "html-to-pdf", "The string must not be empty.", "convert_string_to_stream"), 470);
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
        #
        # * +filename+ - The file name.
        # * *Returns* - The converter object.
        def setZipMainFilename(filename)
            @fields['zip_main_filename'] = filename
            self
        end

        # Set the output page size.
        #
        # * +size+ - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        # * *Returns* - The converter object.
        def setPageSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setPageSize", "html-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            end
            
            @fields['page_size'] = size
            self
        end

        # Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setPageWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            end
            
            @fields['page_width'] = width
            self
        end

        # Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF.
        #
        # * +height+ - The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageHeight(height)
            unless /(?i)^0$|^\-1$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setPageHeight", "html-to-pdf", "The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            end
            
            @fields['page_height'] = height
            self
        end

        # Set the output page dimensions.
        #
        # * +width+ - Set the output page width. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the output page height. Use -1 for a single page PDF. The safe maximum is 200in otherwise some PDF viewers may be unable to open the PDF. The value must be -1 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "html-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # Set the output page top margin.
        #
        # * +top+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # Set the output page right margin.
        #
        # * +right+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # Set the output page bottom margin.
        #
        # * +bottom+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # Set the output page left margin.
        #
        # * +left+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # Disable page margins.
        #
        # * +value+ - Set to true to disable margins.
        # * *Returns* - The converter object.
        def setNoMargins(value)
            @fields['no_margins'] = value
            self
        end

        # Set the output page margins.
        #
        # * +top+ - Set the output page top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +right+ - Set the output page right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +bottom+ - Set the output page bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +left+ - Set the output page left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # Set the page range to print.
        #
        # * +pages+ - A comma separated list of page numbers or ranges. Special strings may be used, such as 'odd', 'even' and 'last'.
        # * *Returns* - The converter object.
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*)|odd|even|last)\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*)|odd|even|last)\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "html-to-pdf", "A comma separated list of page numbers or ranges. Special strings may be used, such as 'odd', 'even' and 'last'.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # Set the viewport width for formatting the HTML content when generating a PDF. By specifying a viewport width, you can control how the content is rendered, ensuring it mimics the appearance on various devices or matches specific design requirements.
        #
        # * +width+ - The width of the viewport. The value must be 'balanced', 'small', 'medium', 'large', 'extra-large', or a number in the range 96-65000px.
        # * *Returns* - The converter object.
        def setContentViewportWidth(width)
            unless /(?i)^(balanced|small|medium|large|extra-large|[0-9]+(px)?)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setContentViewportWidth", "html-to-pdf", "The value must be 'balanced', 'small', 'medium', 'large', 'extra-large', or a number in the range 96-65000px.", "set_content_viewport_width"), 470);
            end
            
            @fields['content_viewport_width'] = width
            self
        end

        # Set the viewport height for formatting the HTML content when generating a PDF. By specifying a viewport height, you can enforce loading of lazy-loaded images and also affect vertical positioning of absolutely positioned elements within the content.
        #
        # * +height+ - The viewport height. The value must be 'auto', 'large', or a number.
        # * *Returns* - The converter object.
        def setContentViewportHeight(height)
            unless /(?i)^(auto|large|[0-9]+(px)?)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setContentViewportHeight", "html-to-pdf", "The value must be 'auto', 'large', or a number.", "set_content_viewport_height"), 470);
            end
            
            @fields['content_viewport_height'] = height
            self
        end

        # Specifies the mode for fitting the HTML content to the print area by upscaling or downscaling it.
        #
        # * +mode+ - The fitting mode. Allowed values are auto, smart-scaling, no-scaling, viewport-width, content-width, single-page, single-page-ratio.
        # * *Returns* - The converter object.
        def setContentFitMode(mode)
            unless /(?i)^(auto|smart-scaling|no-scaling|viewport-width|content-width|single-page|single-page-ratio)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setContentFitMode", "html-to-pdf", "Allowed values are auto, smart-scaling, no-scaling, viewport-width, content-width, single-page, single-page-ratio.", "set_content_fit_mode"), 470);
            end
            
            @fields['content_fit_mode'] = mode
            self
        end

        # Specifies which blank pages to exclude from the output document.
        #
        # * +pages+ - The empty page behavior. Allowed values are trailing, all, none.
        # * *Returns* - The converter object.
        def setRemoveBlankPages(pages)
            unless /(?i)^(trailing|all|none)$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setRemoveBlankPages", "html-to-pdf", "Allowed values are trailing, all, none.", "set_remove_blank_pages"), 470);
            end
            
            @fields['remove_blank_pages'] = pages
            self
        end

        # Load an HTML code from the specified URL and use it as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setHeaderUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setHeaderUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_header_url"), 470);
            end
            
            @fields['header_url'] = url
            self
        end

        # Use the specified HTML code as the page header. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +html+ - The string must not be empty.
        # * *Returns* - The converter object.
        def setHeaderHtml(html)
            if (!(!html.nil? && !html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(html, "setHeaderHtml", "html-to-pdf", "The string must not be empty.", "set_header_html"), 470);
            end
            
            @fields['header_html'] = html
            self
        end

        # Set the header height.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setHeaderHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setHeaderHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_header_height"), 470);
            end
            
            @fields['header_height'] = height
            self
        end

        # Set the file name of the header HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
        #
        # * +filename+ - The file name.
        # * *Returns* - The converter object.
        def setZipHeaderFilename(filename)
            @fields['zip_header_filename'] = filename
            self
        end

        # Load an HTML code from the specified URL and use it as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setFooterUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setFooterUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_footer_url"), 470);
            end
            
            @fields['footer_url'] = url
            self
        end

        # Use the specified HTML as the page footer. The following classes can be used in the HTML. The content of the respective elements will be expanded as follows: pdfcrowd-page-count - the total page count of printed pages pdfcrowd-page-number - the current page number pdfcrowd-source-url - the source URL of the converted document pdfcrowd-source-title - the title of the converted document The following attributes can be used: data-pdfcrowd-number-format - specifies the type of the used numerals. Allowed values: arabic - Arabic numerals, they are used by default roman - Roman numerals eastern-arabic - Eastern Arabic numerals bengali - Bengali numerals devanagari - Devanagari numerals thai - Thai numerals east-asia - Chinese, Vietnamese, Japanese and Korean numerals chinese-formal - Chinese formal numerals Please contact us if you need another type of numerals. Example: <span class='pdfcrowd-page-number' data-pdfcrowd-number-format='roman'></span> data-pdfcrowd-placement - specifies where to place the source URL. Allowed values: The URL is inserted to the content Example: <span class='pdfcrowd-source-url'></span> will produce <span>http://example.com</span> href - the URL is set to the href attribute Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href'>Link to source</a> will produce <a href='http://example.com'>Link to source</a> href-and-content - the URL is set to the href attribute and to the content Example: <a class='pdfcrowd-source-url' data-pdfcrowd-placement='href-and-content'></a> will produce <a href='http://example.com'>http://example.com</a>
        #
        # * +html+ - The string must not be empty.
        # * *Returns* - The converter object.
        def setFooterHtml(html)
            if (!(!html.nil? && !html.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(html, "setFooterHtml", "html-to-pdf", "The string must not be empty.", "set_footer_html"), 470);
            end
            
            @fields['footer_html'] = html
            self
        end

        # Set the footer height.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setFooterHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setFooterHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_footer_height"), 470);
            end
            
            @fields['footer_height'] = height
            self
        end

        # Set the file name of the footer HTML document stored in the input archive. Use this method if the input archive contains multiple HTML documents.
        #
        # * +filename+ - The file name.
        # * *Returns* - The converter object.
        def setZipFooterFilename(filename)
            @fields['zip_footer_filename'] = filename
            self
        end

        # Disable horizontal page margins for header and footer. The header/footer contents width will be equal to the physical page width.
        #
        # * +value+ - Set to true to disable horizontal margins for header and footer.
        # * *Returns* - The converter object.
        def setNoHeaderFooterHorizontalMargins(value)
            @fields['no_header_footer_horizontal_margins'] = value
            self
        end

        # The page header content is not printed on the specified pages. To remove the entire header area, use the conversion config.
        #
        # * +pages+ - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        # * *Returns* - The converter object.
        def setExcludeHeaderOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setExcludeHeaderOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_header_on_pages"), 470);
            end
            
            @fields['exclude_header_on_pages'] = pages
            self
        end

        # The page footer content is not printed on the specified pages. To remove the entire footer area, use the conversion config.
        #
        # * +pages+ - List of physical page numbers. Negative numbers count backwards from the last page: -1 is the last page, -2 is the last but one page, and so on. A comma separated list of page numbers.
        # * *Returns* - The converter object.
        def setExcludeFooterOnPages(pages)
            unless /^(?:\s*\-?\d+\s*,)*\s*\-?\d+\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setExcludeFooterOnPages", "html-to-pdf", "A comma separated list of page numbers.", "set_exclude_footer_on_pages"), 470);
            end
            
            @fields['exclude_footer_on_pages'] = pages
            self
        end

        # Set the scaling factor (zoom) for the header and footer.
        #
        # * +factor+ - The percentage value. The accepted range is 10-500.
        # * *Returns* - The converter object.
        def setHeaderFooterScaleFactor(factor)
            if (!(Integer(factor) >= 10 && Integer(factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setHeaderFooterScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_header_footer_scale_factor"), 470);
            end
            
            @fields['header_footer_scale_factor'] = factor
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

        # Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "html-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "html-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins.
        #
        # * +color+ - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        # * *Returns* - The converter object.
        def setPageBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setPageBackgroundColor", "html-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            end
            
            @fields['page_background_color'] = color
            self
        end

        # Use the print version of the page if available (@media print).
        #
        # * +value+ - Set to true to use the print version of the page.
        # * *Returns* - The converter object.
        def setUsePrintMedia(value)
            @fields['use_print_media'] = value
            self
        end

        # Do not print the background graphics.
        #
        # * +value+ - Set to true to disable the background graphics.
        # * *Returns* - The converter object.
        def setNoBackground(value)
            @fields['no_background'] = value
            self
        end

        # Do not execute JavaScript.
        #
        # * +value+ - Set to true to disable JavaScript in web pages.
        # * *Returns* - The converter object.
        def setDisableJavascript(value)
            @fields['disable_javascript'] = value
            self
        end

        # Do not load images.
        #
        # * +value+ - Set to true to disable loading of images.
        # * *Returns* - The converter object.
        def setDisableImageLoading(value)
            @fields['disable_image_loading'] = value
            self
        end

        # Disable loading fonts from remote sources.
        #
        # * +value+ - Set to true disable loading remote fonts.
        # * *Returns* - The converter object.
        def setDisableRemoteFonts(value)
            @fields['disable_remote_fonts'] = value
            self
        end

        # Use a mobile user agent.
        #
        # * +value+ - Set to true to use a mobile user agent.
        # * *Returns* - The converter object.
        def setUseMobileUserAgent(value)
            @fields['use_mobile_user_agent'] = value
            self
        end

        # Specifies how iframes are handled.
        #
        # * +iframes+ - Allowed values are all, same-origin, none.
        # * *Returns* - The converter object.
        def setLoadIframes(iframes)
            unless /(?i)^(all|same-origin|none)$/.match(iframes)
                raise Error.new(Pdfcrowd.create_invalid_value_message(iframes, "setLoadIframes", "html-to-pdf", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            end
            
            @fields['load_iframes'] = iframes
            self
        end

        # Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        #
        # * +value+ - Set to true to block ads in web pages.
        # * *Returns* - The converter object.
        def setBlockAds(value)
            @fields['block_ads'] = value
            self
        end

        # Set the default HTML content text encoding.
        #
        # * +encoding+ - The text encoding of the HTML content.
        # * *Returns* - The converter object.
        def setDefaultEncoding(encoding)
            @fields['default_encoding'] = encoding
            self
        end

        # Set the locale for the conversion. This may affect the output format of dates, times and numbers.
        #
        # * +locale+ - The locale code according to ISO 639.
        # * *Returns* - The converter object.
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

        # Set HTTP cookies to be included in all requests made by the converter.
        #
        # * +cookies+ - The cookie string.
        # * *Returns* - The converter object.
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # Do not allow insecure HTTPS connections.
        #
        # * +value+ - Set to true to enable SSL certificate verification.
        # * *Returns* - The converter object.
        def setVerifySslCertificates(value)
            @fields['verify_ssl_certificates'] = value
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

        # Do not send the X-Pdfcrowd HTTP header in PDFCrowd HTTP requests.
        #
        # * +value+ - Set to true to disable sending X-Pdfcrowd HTTP header.
        # * *Returns* - The converter object.
        def setNoXpdfcrowdHeader(value)
            @fields['no_xpdfcrowd_header'] = value
            self
        end

        # Specifies behavior in presence of CSS @page rules. It may affect the page size, margins and orientation.
        #
        # * +mode+ - The page rule mode. Allowed values are default, mode1, mode2.
        # * *Returns* - The converter object.
        def setCssPageRuleMode(mode)
            unless /(?i)^(default|mode1|mode2)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setCssPageRuleMode", "html-to-pdf", "Allowed values are default, mode1, mode2.", "set_css_page_rule_mode"), 470);
            end
            
            @fields['css_page_rule_mode'] = mode
            self
        end

        # Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
        #
        # * +css+ - A string containing valid CSS. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "html-to-pdf", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setCustomJavascript", "html-to-pdf", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = javascript
            self
        end

        # Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setOnLoadJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setOnLoadJavascript", "html-to-pdf", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = javascript
            self
        end

        # Set a custom HTTP header to be included in all requests made by the converter.
        #
        # * +header+ - A string containing the header name and value separated by a colon.
        # * *Returns* - The converter object.
        def setCustomHttpHeader(header)
            unless /^.+:.+$/.match(header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header, "setCustomHttpHeader", "html-to-pdf", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = header
            self
        end

        # Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +delay+ - The number of milliseconds to wait. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setJavascriptDelay(delay)
            if (!(Integer(delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(delay, "setJavascriptDelay", "html-to-pdf", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = delay
            self
        end

        # Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setElementToConvert", "html-to-pdf", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
        #
        # * +mode+ - Allowed values are cut-out, remove-siblings, hide-siblings.
        # * *Returns* - The converter object.
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setElementToConvertMode", "html-to-pdf", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setWaitForElement", "html-to-pdf", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # The main HTML element for conversion is detected automatically.
        #
        # * +value+ - Set to true to detect the main element.
        # * *Returns* - The converter object.
        def setAutoDetectElementToConvert(value)
            @fields['auto_detect_element_to_convert'] = value
            self
        end

        # The input HTML is automatically enhanced to improve the readability.
        #
        # * +enhancements+ - Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
        # * *Returns* - The converter object.
        def setReadabilityEnhancements(enhancements)
            unless /(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$/.match(enhancements)
                raise Error.new(Pdfcrowd.create_invalid_value_message(enhancements, "setReadabilityEnhancements", "html-to-pdf", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            end
            
            @fields['readability_enhancements'] = enhancements
            self
        end

        # Set the viewport width in pixels. The viewport is the user's visible area of the page.
        #
        # * +width+ - The accepted range is 96-65000.
        # * *Returns* - The converter object.
        def setViewportWidth(width)
            if (!(Integer(width) >= 96 && Integer(width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setViewportWidth", "html-to-pdf", "The accepted range is 96-65000.", "set_viewport_width"), 470);
            end
            
            @fields['viewport_width'] = width
            self
        end

        # Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000.
        #
        # * +height+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setViewportHeight(height)
            if (!(Integer(height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setViewportHeight", "html-to-pdf", "Must be a positive integer.", "set_viewport_height"), 470);
            end
            
            @fields['viewport_height'] = height
            self
        end

        # Set the viewport size. The viewport is the user's visible area of the page.
        #
        # * +width+ - Set the viewport width in pixels. The viewport is the user's visible area of the page. The accepted range is 96-65000.
        # * +height+ - Set the viewport height in pixels. The viewport is the user's visible area of the page. If the input HTML uses lazily loaded images, try using a large value that covers the entire height of the HTML, e.g. 100000. Must be a positive integer.
        # * *Returns* - The converter object.
        def setViewport(width, height)
            setViewportWidth(width)
            setViewportHeight(height)
            self
        end

        # Set the rendering mode of the page, allowing control over how content is displayed.
        #
        # * +mode+ - The rendering mode. Allowed values are default, viewport.
        # * *Returns* - The converter object.
        def setRenderingMode(mode)
            unless /(?i)^(default|viewport)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setRenderingMode", "html-to-pdf", "Allowed values are default, viewport.", "set_rendering_mode"), 470);
            end
            
            @fields['rendering_mode'] = mode
            self
        end

        # Specifies the scaling mode used for fitting the HTML contents to the print area.
        #
        # * +mode+ - The smart scaling mode. Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.
        # * *Returns* - The converter object.
        def setSmartScalingMode(mode)
            unless /(?i)^(default|disabled|viewport-fit|content-fit|single-page-fit|single-page-fit-ex|mode1)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setSmartScalingMode", "html-to-pdf", "Allowed values are default, disabled, viewport-fit, content-fit, single-page-fit, single-page-fit-ex, mode1.", "set_smart_scaling_mode"), 470);
            end
            
            @fields['smart_scaling_mode'] = mode
            self
        end

        # Set the scaling factor (zoom) for the main page area.
        #
        # * +factor+ - The percentage value. The accepted range is 10-500.
        # * *Returns* - The converter object.
        def setScaleFactor(factor)
            if (!(Integer(factor) >= 10 && Integer(factor) <= 500))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "html-to-pdf", "The accepted range is 10-500.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # Set the quality of embedded JPEG images. A lower quality results in a smaller PDF file but can lead to compression artifacts.
        #
        # * +quality+ - The percentage value. The accepted range is 1-100.
        # * *Returns* - The converter object.
        def setJpegQuality(quality)
            if (!(Integer(quality) >= 1 && Integer(quality) <= 100))
                raise Error.new(Pdfcrowd.create_invalid_value_message(quality, "setJpegQuality", "html-to-pdf", "The accepted range is 1-100.", "set_jpeg_quality"), 470);
            end
            
            @fields['jpeg_quality'] = quality
            self
        end

        # Specify which image types will be converted to JPEG. Converting lossless compression image formats (PNG, GIF, ...) to JPEG may result in a smaller PDF file.
        #
        # * +images+ - The image category. Allowed values are none, opaque, all.
        # * *Returns* - The converter object.
        def setConvertImagesToJpeg(images)
            unless /(?i)^(none|opaque|all)$/.match(images)
                raise Error.new(Pdfcrowd.create_invalid_value_message(images, "setConvertImagesToJpeg", "html-to-pdf", "Allowed values are none, opaque, all.", "set_convert_images_to_jpeg"), 470);
            end
            
            @fields['convert_images_to_jpeg'] = images
            self
        end

        # Set the DPI of images in PDF. A lower DPI may result in a smaller PDF file. If the specified DPI is higher than the actual image DPI, the original image DPI is retained (no upscaling is performed). Use 0 to leave the images unaltered.
        #
        # * +dpi+ - The DPI value. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setImageDpi(dpi)
            if (!(Integer(dpi) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(dpi, "setImageDpi", "html-to-pdf", "Must be a positive integer or 0.", "set_image_dpi"), 470);
            end
            
            @fields['image_dpi'] = dpi
            self
        end

        # Convert HTML forms to fillable PDF forms. Details can be found in the blog post.
        #
        # * +value+ - Set to true to make fillable PDF forms.
        # * *Returns* - The converter object.
        def setEnablePdfForms(value)
            @fields['enable_pdf_forms'] = value
            self
        end

        # Create linearized PDF. This is also known as Fast Web View.
        #
        # * +value+ - Set to true to create linearized PDF.
        # * *Returns* - The converter object.
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # Encrypt the PDF. This prevents search engines from indexing the contents.
        #
        # * +value+ - Set to true to enable PDF encryption.
        # * *Returns* - The converter object.
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        #
        # * +password+ - The user password.
        # * *Returns* - The converter object.
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        #
        # * +password+ - The owner password.
        # * *Returns* - The converter object.
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # Disallow printing of the output PDF.
        #
        # * +value+ - Set to true to set the no-print flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # Disallow modification of the output PDF.
        #
        # * +value+ - Set to true to set the read-only only flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # Disallow text and graphics extraction from the output PDF.
        #
        # * +value+ - Set to true to set the no-copy flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoCopy(value)
            @fields['no_copy'] = value
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

        # Extract meta tags (author, keywords and description) from the input HTML and use them in the output PDF.
        #
        # * +value+ - Set to true to extract meta tags.
        # * *Returns* - The converter object.
        def setExtractMetaTags(value)
            @fields['extract_meta_tags'] = value
            self
        end

        # Specify the page layout to be used when the document is opened.
        #
        # * +layout+ - Allowed values are single-page, one-column, two-column-left, two-column-right.
        # * *Returns* - The converter object.
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "html-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # Specify how the document should be displayed when opened.
        #
        # * +mode+ - Allowed values are full-screen, thumbnails, outlines.
        # * *Returns* - The converter object.
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "html-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # Specify how the page should be displayed when opened.
        #
        # * +zoom_type+ - Allowed values are fit-width, fit-height, fit-page.
        # * *Returns* - The converter object.
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "html-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # Display the specified page when the document is opened.
        #
        # * +page+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "html-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # Specify the initial page zoom in percents when the document is opened.
        #
        # * +zoom+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "html-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # Specify whether to hide the viewer application's tool bars when the document is active.
        #
        # * +value+ - Set to true to hide tool bars.
        # * *Returns* - The converter object.
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # Specify whether to hide the viewer application's menu bar when the document is active.
        #
        # * +value+ - Set to true to hide the menu bar.
        # * *Returns* - The converter object.
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        #
        # * +value+ - Set to true to hide ui elements.
        # * *Returns* - The converter object.
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # Specify whether to resize the document's window to fit the size of the first displayed page.
        #
        # * +value+ - Set to true to resize the window.
        # * *Returns* - The converter object.
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # Specify whether to position the document's window in the center of the screen.
        #
        # * +value+ - Set to true to center the window.
        # * *Returns* - The converter object.
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        #
        # * +value+ - Set to true to display the title.
        # * *Returns* - The converter object.
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        #
        # * +value+ - Set to true to set right-to-left reading order.
        # * *Returns* - The converter object.
        def setRightToLeft(value)
            @fields['right_to_left'] = value
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "setDataFormat", "html-to-pdf", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # Set the encoding of the data file set by setDataFile.
        #
        # * +encoding+ - The data file encoding.
        # * *Returns* - The converter object.
        def setDataEncoding(encoding)
            @fields['data_encoding'] = encoding
            self
        end

        # Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
        #
        # * +value+ - Set to true to ignore undefined variables.
        # * *Returns* - The converter object.
        def setDataIgnoreUndefined(value)
            @fields['data_ignore_undefined'] = value
            self
        end

        # Auto escape HTML symbols in the input data before placing them into the output.
        #
        # * +value+ - Set to true to turn auto escaping on.
        # * *Returns* - The converter object.
        def setDataAutoEscape(value)
            @fields['data_auto_escape'] = value
            self
        end

        # Auto trim whitespace around each template command block.
        #
        # * +value+ - Set to true to turn auto trimming on.
        # * *Returns* - The converter object.
        def setDataTrimBlocks(value)
            @fields['data_trim_blocks'] = value
            self
        end

        # Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
        #
        # * +options+ - Comma separated list of options.
        # * *Returns* - The converter object.
        def setDataOptions(options)
            @fields['data_options'] = options
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the total number of pages in the original output document, including the pages excluded by setPrintPageRange().
        # * *Returns* - The total page count.
        def getTotalPageCount()
            return @helper.getTotalPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "html-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # A client certificate to authenticate the converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        #
        # * +certificate+ - The file must be in PKCS12 format. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setClientCertificate(certificate)
            if (!(File.file?(certificate) && !File.zero?(certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(certificate, "setClientCertificate", "html-to-pdf", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = certificate
            self
        end

        # A password for PKCS12 file with a client certificate if it is needed.
        #
        # * +password+ -
        # * *Returns* - The converter object.
        def setClientCertificatePassword(password)
            @fields['client_certificate_password'] = password
            self
        end

        # Set the internal DPI resolution used for positioning of PDF contents. It can help in situations when there are small inaccuracies in the PDF. It is recommended to use values that are a multiple of 72, such as 288 or 360.
        #
        # * +dpi+ - The DPI value. The accepted range is 72-600.
        # * *Returns* - The converter object.
        def setLayoutDpi(dpi)
            if (!(Integer(dpi) >= 72 && Integer(dpi) <= 600))
                raise Error.new(Pdfcrowd.create_invalid_value_message(dpi, "setLayoutDpi", "html-to-pdf", "The accepted range is 72-600.", "set_layout_dpi"), 470);
            end
            
            @fields['layout_dpi'] = dpi
            self
        end

        # Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        #
        # * +x+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
        # * *Returns* - The converter object.
        def setContentAreaX(x)
            unless /(?i)^0$|^\-?[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setContentAreaX", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_x"), 470);
            end
            
            @fields['content_area_x'] = x
            self
        end

        # Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        #
        # * +y+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
        # * *Returns* - The converter object.
        def setContentAreaY(y)
            unless /(?i)^0$|^\-?[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setContentAreaY", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.", "set_content_area_y"), 470);
            end
            
            @fields['content_area_y'] = y
            self
        end

        # Set the width of the content area. It should be at least 1 inch.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setContentAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setContentAreaWidth", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_width"), 470);
            end
            
            @fields['content_area_width'] = width
            self
        end

        # Set the height of the content area. It should be at least 1 inch.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setContentAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setContentAreaHeight", "html-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_content_area_height"), 470);
            end
            
            @fields['content_area_height'] = height
            self
        end

        # Set the content area position and size. The content area enables to specify a web page area to be converted.
        #
        # * +x+ - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
        # * +y+ - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'. It may contain a negative value.
        # * +width+ - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setContentArea(x, y, width, height)
            setContentAreaX(x)
            setContentAreaY(y)
            setContentAreaWidth(width)
            setContentAreaHeight(height)
            self
        end

        # A 2D transformation matrix applied to the main contents on each page. The origin [0,0] is located at the top-left corner of the contents. The resolution is 72 dpi.
        #
        # * +matrix+ - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        # * *Returns* - The converter object.
        def setContentsMatrix(matrix)
            @fields['contents_matrix'] = matrix
            self
        end

        # A 2D transformation matrix applied to the page header contents. The origin [0,0] is located at the top-left corner of the header. The resolution is 72 dpi.
        #
        # * +matrix+ - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        # * *Returns* - The converter object.
        def setHeaderMatrix(matrix)
            @fields['header_matrix'] = matrix
            self
        end

        # A 2D transformation matrix applied to the page footer contents. The origin [0,0] is located at the top-left corner of the footer. The resolution is 72 dpi.
        #
        # * +matrix+ - A comma separated string of matrix elements: "scaleX,skewX,transX,skewY,scaleY,transY"
        # * *Returns* - The converter object.
        def setFooterMatrix(matrix)
            @fields['footer_matrix'] = matrix
            self
        end

        # Disable automatic height adjustment that compensates for pixel to point rounding errors.
        #
        # * +value+ - Set to true to disable automatic height scale.
        # * *Returns* - The converter object.
        def setDisablePageHeightOptimization(value)
            @fields['disable_page_height_optimization'] = value
            self
        end

        # Add special CSS classes to the main document's body element. This allows applying custom styling based on these classes: pdfcrowd-page-X - where X is the current page number pdfcrowd-page-odd - odd page pdfcrowd-page-even - even page
        # Warning: If your custom styling affects the contents area size (e.g. by using different margins, padding, border width), the resulting PDF may contain duplicit contents or some contents may be missing.
        #
        # * +value+ - Set to true to add the special CSS classes.
        # * *Returns* - The converter object.
        def setMainDocumentCssAnnotation(value)
            @fields['main_document_css_annotation'] = value
            self
        end

        # Add special CSS classes to the header/footer's body element. This allows applying custom styling based on these classes: pdfcrowd-page-X - where X is the current page number pdfcrowd-page-count-X - where X is the total page count pdfcrowd-page-first - the first page pdfcrowd-page-last - the last page pdfcrowd-page-odd - odd page pdfcrowd-page-even - even page
        #
        # * +value+ - Set to true to add the special CSS classes.
        # * *Returns* - The converter object.
        def setHeaderFooterCssAnnotation(value)
            @fields['header_footer_css_annotation'] = value
            self
        end

        # Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
        #
        # * +max_time+ - The number of seconds to wait. The accepted range is 10-30.
        # * *Returns* - The converter object.
        def setMaxLoadingTime(max_time)
            if (!(Integer(max_time) >= 10 && Integer(max_time) <= 30))
                raise Error.new(Pdfcrowd.create_invalid_value_message(max_time, "setMaxLoadingTime", "html-to-pdf", "The accepted range is 10-30.", "set_max_loading_time"), 470);
            end
            
            @fields['max_loading_time'] = max_time
            self
        end

        # Allows to configure conversion via JSON. The configuration defines various page settings for individual PDF pages or ranges of pages. It provides flexibility in designing each page of the PDF, giving control over each page's size, header, footer etc. If a page or parameter is not explicitly specified, the system will use the default settings for that page or attribute. If a JSON configuration is provided, the settings in the JSON will take precedence over the global options. The structure of the JSON must be: pageSetup: An array of objects where each object defines the configuration for a specific page or range of pages. The following properties can be set for each page object: pages: A comma-separated list of page numbers or ranges. Special strings may be used, such as `odd`, `even` and `last`. For example: 1-: from page 1 to the end of the document 2: only the 2nd page 2,4,6: pages 2, 4, and 6 2-5: pages 2 through 5 odd,2: the 2nd page and all odd pages pageSize: The page size (optional). Possible values: A0, A1, A2, A3, A4, A5, A6, Letter. pageWidth: The width of the page (optional). pageHeight: The height of the page (optional). marginLeft: Left margin (optional). marginRight: Right margin (optional). marginTop: Top margin (optional). marginBottom: Bottom margin (optional). displayHeader: Header appearance (optional). Possible values: none: completely excluded space: only the content is excluded, the space is used content: the content is printed (default) displayFooter: Footer appearance (optional). Possible values: none: completely excluded space: only the content is excluded, the space is used content: the content is printed (default) headerHeight: Height of the header (optional). footerHeight: Height of the footer (optional). orientation: Page orientation, such as "portrait" or "landscape" (optional). backgroundColor: Page background color in RRGGBB or RRGGBBAA hexadecimal format (optional). Dimensions may be empty, 0 or specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        #
        # * +json_string+ - The JSON string.
        # * *Returns* - The converter object.
        def setConversionConfig(json_string)
            @fields['conversion_config'] = json_string
            self
        end

        # Allows to configure the conversion process via JSON file. See details of the JSON string.
        #
        # * +filepath+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
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

        # Specifies the User-Agent HTTP header that will be used by the converter when a request is made to the converted web page.
        #
        # * +agent+ - The user agent.
        # * *Returns* - The converter object.
        def setConverterUserAgent(agent)
            @fields['converter_user_agent'] = agent
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "html-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from HTML to image.
    class HtmlToImageClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "html-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # Convert a web page.
        #
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "html-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a web page and write the result to an output stream.
        #
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "html-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a web page and write the result to a local file.
        #
        # * +url+ - The address of the web page to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file can be either a single file or an archive (.tar.gz, .tar.bz2, or .zip). If the HTML document refers to local external assets (images, style sheets, javascript), zip the document together with the assets. The file must exist and not be empty. The file name must have a valid extension.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "html-to-image", "The file must exist and not be empty.", "convert_file"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "html-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
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

        # Convert a string.
        #
        # * +text+ - The string content to convert. The string must not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertString(text)
            if (!(!text.nil? && !text.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertString", "html-to-image", "The string must not be empty.", "convert_string"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(text, "convertStringToStream::text", "html-to-image", "The string must not be empty.", "convert_string_to_stream"), 470);
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data. The stream can contain either HTML code or an archive (.zip, .tar.gz, .tar.bz2).The archive can contain HTML code and its external assets (images, style sheets, javascript).
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Set the file name of the main HTML document stored in the input archive. If not specified, the first HTML file in the archive is used for conversion. Use this method if the input archive contains multiple HTML documents.
        #
        # * +filename+ - The file name.
        # * *Returns* - The converter object.
        def setZipMainFilename(filename)
            @fields['zip_main_filename'] = filename
            self
        end

        # Set the output image width in pixels.
        #
        # * +width+ - The accepted range is 96-65000.
        # * *Returns* - The converter object.
        def setScreenshotWidth(width)
            if (!(Integer(width) >= 96 && Integer(width) <= 65000))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setScreenshotWidth", "html-to-image", "The accepted range is 96-65000.", "set_screenshot_width"), 470);
            end
            
            @fields['screenshot_width'] = width
            self
        end

        # Set the output image height in pixels. If it is not specified, actual document height is used.
        #
        # * +height+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setScreenshotHeight(height)
            if (!(Integer(height) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setScreenshotHeight", "html-to-image", "Must be a positive integer.", "set_screenshot_height"), 470);
            end
            
            @fields['screenshot_height'] = height
            self
        end

        # Set the scaling factor (zoom) for the output image.
        #
        # * +factor+ - The percentage value. Must be a positive integer.
        # * *Returns* - The converter object.
        def setScaleFactor(factor)
            if (!(Integer(factor) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "html-to-image", "Must be a positive integer.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # The output image background color.
        #
        # * +color+ - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        # * *Returns* - The converter object.
        def setBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setBackgroundColor", "html-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_background_color"), 470);
            end
            
            @fields['background_color'] = color
            self
        end

        # Use the print version of the page if available (@media print).
        #
        # * +value+ - Set to true to use the print version of the page.
        # * *Returns* - The converter object.
        def setUsePrintMedia(value)
            @fields['use_print_media'] = value
            self
        end

        # Do not print the background graphics.
        #
        # * +value+ - Set to true to disable the background graphics.
        # * *Returns* - The converter object.
        def setNoBackground(value)
            @fields['no_background'] = value
            self
        end

        # Do not execute JavaScript.
        #
        # * +value+ - Set to true to disable JavaScript in web pages.
        # * *Returns* - The converter object.
        def setDisableJavascript(value)
            @fields['disable_javascript'] = value
            self
        end

        # Do not load images.
        #
        # * +value+ - Set to true to disable loading of images.
        # * *Returns* - The converter object.
        def setDisableImageLoading(value)
            @fields['disable_image_loading'] = value
            self
        end

        # Disable loading fonts from remote sources.
        #
        # * +value+ - Set to true disable loading remote fonts.
        # * *Returns* - The converter object.
        def setDisableRemoteFonts(value)
            @fields['disable_remote_fonts'] = value
            self
        end

        # Use a mobile user agent.
        #
        # * +value+ - Set to true to use a mobile user agent.
        # * *Returns* - The converter object.
        def setUseMobileUserAgent(value)
            @fields['use_mobile_user_agent'] = value
            self
        end

        # Specifies how iframes are handled.
        #
        # * +iframes+ - Allowed values are all, same-origin, none.
        # * *Returns* - The converter object.
        def setLoadIframes(iframes)
            unless /(?i)^(all|same-origin|none)$/.match(iframes)
                raise Error.new(Pdfcrowd.create_invalid_value_message(iframes, "setLoadIframes", "html-to-image", "Allowed values are all, same-origin, none.", "set_load_iframes"), 470);
            end
            
            @fields['load_iframes'] = iframes
            self
        end

        # Try to block ads. Enabling this option can produce smaller output and speed up the conversion.
        #
        # * +value+ - Set to true to block ads in web pages.
        # * *Returns* - The converter object.
        def setBlockAds(value)
            @fields['block_ads'] = value
            self
        end

        # Set the default HTML content text encoding.
        #
        # * +encoding+ - The text encoding of the HTML content.
        # * *Returns* - The converter object.
        def setDefaultEncoding(encoding)
            @fields['default_encoding'] = encoding
            self
        end

        # Set the locale for the conversion. This may affect the output format of dates, times and numbers.
        #
        # * +locale+ - The locale code according to ISO 639.
        # * *Returns* - The converter object.
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

        # Set HTTP cookies to be included in all requests made by the converter.
        #
        # * +cookies+ - The cookie string.
        # * *Returns* - The converter object.
        def setCookies(cookies)
            @fields['cookies'] = cookies
            self
        end

        # Do not allow insecure HTTPS connections.
        #
        # * +value+ - Set to true to enable SSL certificate verification.
        # * *Returns* - The converter object.
        def setVerifySslCertificates(value)
            @fields['verify_ssl_certificates'] = value
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

        # Do not send the X-Pdfcrowd HTTP header in PDFCrowd HTTP requests.
        #
        # * +value+ - Set to true to disable sending X-Pdfcrowd HTTP header.
        # * *Returns* - The converter object.
        def setNoXpdfcrowdHeader(value)
            @fields['no_xpdfcrowd_header'] = value
            self
        end

        # Apply custom CSS to the input HTML document. It allows you to modify the visual appearance and layout of your HTML content dynamically. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
        #
        # * +css+ - A string containing valid CSS. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "html-to-image", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # Run a custom JavaScript after the document is loaded and ready to print. The script is intended for post-load DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setCustomJavascript", "html-to-image", "The string must not be empty.", "set_custom_javascript"), 470);
            end
            
            @fields['custom_javascript'] = javascript
            self
        end

        # Run a custom JavaScript right after the document is loaded. The script is intended for early DOM manipulation (add/remove elements, update CSS, ...). In addition to the standard browser APIs, the custom JavaScript code can use helper functions from our JavaScript library.
        #
        # * +javascript+ - A string containing a JavaScript code. The string must not be empty.
        # * *Returns* - The converter object.
        def setOnLoadJavascript(javascript)
            if (!(!javascript.nil? && !javascript.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(javascript, "setOnLoadJavascript", "html-to-image", "The string must not be empty.", "set_on_load_javascript"), 470);
            end
            
            @fields['on_load_javascript'] = javascript
            self
        end

        # Set a custom HTTP header to be included in all requests made by the converter.
        #
        # * +header+ - A string containing the header name and value separated by a colon.
        # * *Returns* - The converter object.
        def setCustomHttpHeader(header)
            unless /^.+:.+$/.match(header)
                raise Error.new(Pdfcrowd.create_invalid_value_message(header, "setCustomHttpHeader", "html-to-image", "A string containing the header name and value separated by a colon.", "set_custom_http_header"), 470);
            end
            
            @fields['custom_http_header'] = header
            self
        end

        # Wait the specified number of milliseconds to finish all JavaScript after the document is loaded. Your license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +delay+ - The number of milliseconds to wait. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setJavascriptDelay(delay)
            if (!(Integer(delay) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(delay, "setJavascriptDelay", "html-to-image", "Must be a positive integer or 0.", "set_javascript_delay"), 470);
            end
            
            @fields['javascript_delay'] = delay
            self
        end

        # Convert only the specified element from the main document and its children. The element is specified by one or more CSS selectors. If the element is not found, the conversion fails. If multiple elements are found, the first one is used.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setElementToConvert(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setElementToConvert", "html-to-image", "The string must not be empty.", "set_element_to_convert"), 470);
            end
            
            @fields['element_to_convert'] = selectors
            self
        end

        # Specify the DOM handling when only a part of the document is converted. This can affect the CSS rules used.
        #
        # * +mode+ - Allowed values are cut-out, remove-siblings, hide-siblings.
        # * *Returns* - The converter object.
        def setElementToConvertMode(mode)
            unless /(?i)^(cut-out|remove-siblings|hide-siblings)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setElementToConvertMode", "html-to-image", "Allowed values are cut-out, remove-siblings, hide-siblings.", "set_element_to_convert_mode"), 470);
            end
            
            @fields['element_to_convert_mode'] = mode
            self
        end

        # Wait for the specified element in a source document. The element is specified by one or more CSS selectors. The element is searched for in the main document and all iframes. If the element is not found, the conversion fails. Your license defines the maximum wait time by "Max Delay" parameter.
        #
        # * +selectors+ - One or more CSS selectors separated by commas. The string must not be empty.
        # * *Returns* - The converter object.
        def setWaitForElement(selectors)
            if (!(!selectors.nil? && !selectors.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(selectors, "setWaitForElement", "html-to-image", "The string must not be empty.", "set_wait_for_element"), 470);
            end
            
            @fields['wait_for_element'] = selectors
            self
        end

        # The main HTML element for conversion is detected automatically.
        #
        # * +value+ - Set to true to detect the main element.
        # * *Returns* - The converter object.
        def setAutoDetectElementToConvert(value)
            @fields['auto_detect_element_to_convert'] = value
            self
        end

        # The input HTML is automatically enhanced to improve the readability.
        #
        # * +enhancements+ - Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.
        # * *Returns* - The converter object.
        def setReadabilityEnhancements(enhancements)
            unless /(?i)^(none|readability-v1|readability-v2|readability-v3|readability-v4)$/.match(enhancements)
                raise Error.new(Pdfcrowd.create_invalid_value_message(enhancements, "setReadabilityEnhancements", "html-to-image", "Allowed values are none, readability-v1, readability-v2, readability-v3, readability-v4.", "set_readability_enhancements"), 470);
            end
            
            @fields['readability_enhancements'] = enhancements
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(data_format, "setDataFormat", "html-to-image", "Allowed values are auto, json, xml, yaml, csv.", "set_data_format"), 470);
            end
            
            @fields['data_format'] = data_format
            self
        end

        # Set the encoding of the data file set by setDataFile.
        #
        # * +encoding+ - The data file encoding.
        # * *Returns* - The converter object.
        def setDataEncoding(encoding)
            @fields['data_encoding'] = encoding
            self
        end

        # Ignore undefined variables in the HTML template. The default mode is strict so any undefined variable causes the conversion to fail. You can use {% if variable is defined %} to check if the variable is defined.
        #
        # * +value+ - Set to true to ignore undefined variables.
        # * *Returns* - The converter object.
        def setDataIgnoreUndefined(value)
            @fields['data_ignore_undefined'] = value
            self
        end

        # Auto escape HTML symbols in the input data before placing them into the output.
        #
        # * +value+ - Set to true to turn auto escaping on.
        # * *Returns* - The converter object.
        def setDataAutoEscape(value)
            @fields['data_auto_escape'] = value
            self
        end

        # Auto trim whitespace around each template command block.
        #
        # * +value+ - Set to true to turn auto trimming on.
        # * *Returns* - The converter object.
        def setDataTrimBlocks(value)
            @fields['data_trim_blocks'] = value
            self
        end

        # Set the advanced data options:csv_delimiter - The CSV data delimiter, the default is ,.xml_remove_root - Remove the root XML element from the input data.data_root - The name of the root element inserted into the input data without a root node (e.g. CSV), the default is data.
        #
        # * +options+ - Comma separated list of options.
        # * *Returns* - The converter object.
        def setDataOptions(options)
            @fields['data_options'] = options
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "html-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # A client certificate to authenticate the converter on your web server. The certificate is used for two-way SSL/TLS authentication and adds extra security.
        #
        # * +certificate+ - The file must be in PKCS12 format. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setClientCertificate(certificate)
            if (!(File.file?(certificate) && !File.zero?(certificate)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(certificate, "setClientCertificate", "html-to-image", "The file must exist and not be empty.", "set_client_certificate"), 470);
            end
            
            @files['client_certificate'] = certificate
            self
        end

        # A password for PKCS12 file with a client certificate if it is needed.
        #
        # * +password+ -
        # * *Returns* - The converter object.
        def setClientCertificatePassword(password)
            @fields['client_certificate_password'] = password
            self
        end

        # Set the maximum time to load the page and its resources. After this time, all requests will be considered successful. This can be useful to ensure that the conversion does not timeout. Use this method if there is no other way to fix page loading.
        #
        # * +max_time+ - The number of seconds to wait. The accepted range is 10-30.
        # * *Returns* - The converter object.
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

        # Specifies the User-Agent HTTP header that will be used by the converter when a request is made to the converted web page.
        #
        # * +agent+ - The user agent.
        # * *Returns* - The converter object.
        def setConverterUserAgent(agent)
            @fields['converter_user_agent'] = agent
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "html-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from one image format to another image format.
    class ImageToImageClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
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
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "image-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert an image and write the result to an output stream.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "image-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert an image and write the result to a local file.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "image-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "image-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # The format of the output file.
        #
        # * +output_format+ - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        # * *Returns* - The converter object.
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "image-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
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

        # Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        #
        # * +x+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaX(x)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        #
        # * +y+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaY(y)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # Set the width of the content area. It should be at least 1 inch.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # Set the height of the content area. It should be at least 1 inch.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # Set the content area position and size. The content area enables to specify the part to be converted.
        #
        # * +x+ - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +y+ - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +width+ - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # Remove borders of an image which does not change in color.
        #
        # * +value+ - Set to true to remove borders.
        # * *Returns* - The converter object.
        def setRemoveBorders(value)
            @fields['remove_borders'] = value
            self
        end

        # Set the output canvas size.
        #
        # * +size+ - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        # * *Returns* - The converter object.
        def setCanvasSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setCanvasSize", "image-to-image", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_canvas_size"), 470);
            end
            
            @fields['canvas_size'] = size
            self
        end

        # Set the output canvas width.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCanvasWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCanvasWidth", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_width"), 470);
            end
            
            @fields['canvas_width'] = width
            self
        end

        # Set the output canvas height.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCanvasHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCanvasHeight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_canvas_height"), 470);
            end
            
            @fields['canvas_height'] = height
            self
        end

        # Set the output canvas dimensions. If no canvas size is specified, margins are applied as a border around the image.
        #
        # * +width+ - Set the output canvas width. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the output canvas height. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCanvasDimensions(width, height)
            setCanvasWidth(width)
            setCanvasHeight(height)
            self
        end

        # Set the output canvas orientation.
        #
        # * +orientation+ - Allowed values are landscape, portrait.
        # * *Returns* - The converter object.
        def setOrientation(orientation)
            unless /(?i)^(landscape|portrait)$/.match(orientation)
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "image-to-image", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # Set the image position on the canvas.
        #
        # * +position+ - Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
        # * *Returns* - The converter object.
        def setPosition(position)
            unless /(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$/.match(position)
                raise Error.new(Pdfcrowd.create_invalid_value_message(position, "setPosition", "image-to-image", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            end
            
            @fields['position'] = position
            self
        end

        # Set the mode to print the image on the canvas.
        #
        # * +mode+ - Allowed values are default, fit, stretch.
        # * *Returns* - The converter object.
        def setPrintCanvasMode(mode)
            unless /(?i)^(default|fit|stretch)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPrintCanvasMode", "image-to-image", "Allowed values are default, fit, stretch.", "set_print_canvas_mode"), 470);
            end
            
            @fields['print_canvas_mode'] = mode
            self
        end

        # Set the output canvas top margin.
        #
        # * +top+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # Set the output canvas right margin.
        #
        # * +right+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # Set the output canvas bottom margin.
        #
        # * +bottom+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # Set the output canvas left margin.
        #
        # * +left+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "image-to-image", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # Set the output canvas margins.
        #
        # * +top+ - Set the output canvas top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +right+ - Set the output canvas right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +bottom+ - Set the output canvas bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +left+ - Set the output canvas left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # The canvas background color in RGB or RGBA hexadecimal format. The color fills the entire canvas regardless of margins. If no canvas size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
        #
        # * +color+ - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        # * *Returns* - The converter object.
        def setCanvasBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setCanvasBackgroundColor", "image-to-image", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_canvas_background_color"), 470);
            end
            
            @fields['canvas_background_color'] = color
            self
        end

        # Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
        #
        # * +dpi+ - The DPI value.
        # * *Returns* - The converter object.
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "image-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "image-to-image", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to PDF.
    class PdfToPdfClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
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
        # * +action+ - Allowed values are join, shuffle, extract, delete.
        # * *Returns* - The converter object.
        def setAction(action)
            unless /(?i)^(join|shuffle|extract|delete)$/.match(action)
                raise Error.new(Pdfcrowd.create_invalid_value_message(action, "setAction", "pdf-to-pdf", "Allowed values are join, shuffle, extract, delete.", "set_action"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "convertToFile", "pdf-to-pdf", "The string must not be empty.", "convert_to_file"), 470);
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(file_path, "addPdfFile", "pdf-to-pdf", "The file must exist and not be empty.", "add_pdf_file"), 470);
            end
            
            @files['f_%s' % @file_id] = file_path
            @file_id += 1
            self
        end

        # Add in-memory raw PDF data to the list of the input PDFs.Typical usage is for adding PDF created by another PDFCrowd converter. Example in PHP: $clientPdf2Pdf->addPdfRawData($clientHtml2Pdf->convertUrl('http://www.example.com'));
        #
        # * +data+ - The raw PDF data. The input data must be PDF content.
        # * *Returns* - The converter object.
        def addPdfRawData(data)
            if (!(!data.nil? && data.length > 300 and data[0...4] == '%PDF'))
                raise Error.new(Pdfcrowd.create_invalid_value_message("raw PDF data", "addPdfRawData", "pdf-to-pdf", "The input data must be PDF content.", "add_pdf_raw_data"), 470);
            end
            
            @raw_data['f_%s' % @file_id] = data
            @file_id += 1
            self
        end

        # Password to open the encrypted PDF file.
        #
        # * +password+ - The input PDF password.
        # * *Returns* - The converter object.
        def setInputPdfPassword(password)
            @fields['input_pdf_password'] = password
            self
        end

        # Set the page range for extract or delete action.
        #
        # * +pages+ - A comma separated list of page numbers or ranges.
        # * *Returns* - The converter object.
        def setPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPageRange", "pdf-to-pdf", "A comma separated list of page numbers or ranges.", "set_page_range"), 470);
            end
            
            @fields['page_range'] = pages
            self
        end

        # Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "pdf-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "pdf-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # Create linearized PDF. This is also known as Fast Web View.
        #
        # * +value+ - Set to true to create linearized PDF.
        # * *Returns* - The converter object.
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # Encrypt the PDF. This prevents search engines from indexing the contents.
        #
        # * +value+ - Set to true to enable PDF encryption.
        # * *Returns* - The converter object.
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        #
        # * +password+ - The user password.
        # * *Returns* - The converter object.
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        #
        # * +password+ - The owner password.
        # * *Returns* - The converter object.
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # Disallow printing of the output PDF.
        #
        # * +value+ - Set to true to set the no-print flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # Disallow modification of the output PDF.
        #
        # * +value+ - Set to true to set the read-only only flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # Disallow text and graphics extraction from the output PDF.
        #
        # * +value+ - Set to true to set the no-copy flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoCopy(value)
            @fields['no_copy'] = value
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

        # Use metadata (title, subject, author and keywords) from the n-th input PDF.
        #
        # * +index+ - Set the index of the input PDF file from which to use the metadata. 0 means no metadata. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setUseMetadataFrom(index)
            if (!(Integer(index) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(index, "setUseMetadataFrom", "pdf-to-pdf", "Must be a positive integer or 0.", "set_use_metadata_from"), 470);
            end
            
            @fields['use_metadata_from'] = index
            self
        end

        # Specify the page layout to be used when the document is opened.
        #
        # * +layout+ - Allowed values are single-page, one-column, two-column-left, two-column-right.
        # * *Returns* - The converter object.
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "pdf-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # Specify how the document should be displayed when opened.
        #
        # * +mode+ - Allowed values are full-screen, thumbnails, outlines.
        # * *Returns* - The converter object.
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "pdf-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # Specify how the page should be displayed when opened.
        #
        # * +zoom_type+ - Allowed values are fit-width, fit-height, fit-page.
        # * *Returns* - The converter object.
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "pdf-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # Display the specified page when the document is opened.
        #
        # * +page+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "pdf-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # Specify the initial page zoom in percents when the document is opened.
        #
        # * +zoom+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "pdf-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # Specify whether to hide the viewer application's tool bars when the document is active.
        #
        # * +value+ - Set to true to hide tool bars.
        # * *Returns* - The converter object.
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # Specify whether to hide the viewer application's menu bar when the document is active.
        #
        # * +value+ - Set to true to hide the menu bar.
        # * *Returns* - The converter object.
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        #
        # * +value+ - Set to true to hide ui elements.
        # * *Returns* - The converter object.
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # Specify whether to resize the document's window to fit the size of the first displayed page.
        #
        # * +value+ - Set to true to resize the window.
        # * *Returns* - The converter object.
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # Specify whether to position the document's window in the center of the screen.
        #
        # * +value+ - Set to true to center the window.
        # * *Returns* - The converter object.
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        #
        # * +value+ - Set to true to display the title.
        # * *Returns* - The converter object.
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # Set the predominant reading order for text to right-to-left. This option has no direct effect on the document's contents or page numbering but can be used to determine the relative positioning of pages when displayed side by side or printed n-up
        #
        # * +value+ - Set to true to set right-to-left reading order.
        # * *Returns* - The converter object.
        def setRightToLeft(value)
            @fields['right_to_left'] = value
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "pdf-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from an image to PDF.
    class ImageToPdfClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
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
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert an image and write the result to an output stream.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "image-to-pdf", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert an image and write the result to a local file.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "image-to-pdf", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "image-to-pdf", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area.
        #
        # * +x+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaX(x)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(x)
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area.
        #
        # * +y+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaY(y)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(y)
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # Set the width of the content area. It should be at least 1 inch.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # Set the height of the content area. It should be at least 1 inch.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropAreaHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # Set the content area position and size. The content area enables to specify the part to be converted.
        #
        # * +x+ - Set the top left X coordinate of the content area. It is relative to the top left X coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +y+ - Set the top left Y coordinate of the content area. It is relative to the top left Y coordinate of the print area. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +width+ - Set the width of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the height of the content area. It should be at least 1 inch. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # Remove borders of an image which does not change in color.
        #
        # * +value+ - Set to true to remove borders.
        # * *Returns* - The converter object.
        def setRemoveBorders(value)
            @fields['remove_borders'] = value
            self
        end

        # Set the output page size.
        #
        # * +size+ - Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.
        # * *Returns* - The converter object.
        def setPageSize(size)
            unless /(?i)^(A0|A1|A2|A3|A4|A5|A6|Letter)$/.match(size)
                raise Error.new(Pdfcrowd.create_invalid_value_message(size, "setPageSize", "image-to-pdf", "Allowed values are A0, A1, A2, A3, A4, A5, A6, Letter.", "set_page_size"), 470);
            end
            
            @fields['page_size'] = size
            self
        end

        # Set the output page width.
        #
        # * +width+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageWidth(width)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(width)
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setPageWidth", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_width"), 470);
            end
            
            @fields['page_width'] = width
            self
        end

        # Set the output page height.
        #
        # * +height+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageHeight(height)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(height)
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setPageHeight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_page_height"), 470);
            end
            
            @fields['page_height'] = height
            self
        end

        # Set the output page dimensions. If no page size is specified, margins are applied as a border around the image.
        #
        # * +width+ - Set the output page width. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +height+ - Set the output page height. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
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
                raise Error.new(Pdfcrowd.create_invalid_value_message(orientation, "setOrientation", "image-to-pdf", "Allowed values are landscape, portrait.", "set_orientation"), 470);
            end
            
            @fields['orientation'] = orientation
            self
        end

        # Set the image position on the page.
        #
        # * +position+ - Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.
        # * *Returns* - The converter object.
        def setPosition(position)
            unless /(?i)^(center|top|bottom|left|right|top-left|top-right|bottom-left|bottom-right)$/.match(position)
                raise Error.new(Pdfcrowd.create_invalid_value_message(position, "setPosition", "image-to-pdf", "Allowed values are center, top, bottom, left, right, top-left, top-right, bottom-left, bottom-right.", "set_position"), 470);
            end
            
            @fields['position'] = position
            self
        end

        # Set the mode to print the image on the content area of the page.
        #
        # * +mode+ - Allowed values are default, fit, stretch.
        # * *Returns* - The converter object.
        def setPrintPageMode(mode)
            unless /(?i)^(default|fit|stretch)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPrintPageMode", "image-to-pdf", "Allowed values are default, fit, stretch.", "set_print_page_mode"), 470);
            end
            
            @fields['print_page_mode'] = mode
            self
        end

        # Set the output page top margin.
        #
        # * +top+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginTop(top)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(top)
                raise Error.new(Pdfcrowd.create_invalid_value_message(top, "setMarginTop", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_top"), 470);
            end
            
            @fields['margin_top'] = top
            self
        end

        # Set the output page right margin.
        #
        # * +right+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginRight(right)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(right)
                raise Error.new(Pdfcrowd.create_invalid_value_message(right, "setMarginRight", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_right"), 470);
            end
            
            @fields['margin_right'] = right
            self
        end

        # Set the output page bottom margin.
        #
        # * +bottom+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginBottom(bottom)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(bottom)
                raise Error.new(Pdfcrowd.create_invalid_value_message(bottom, "setMarginBottom", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_bottom"), 470);
            end
            
            @fields['margin_bottom'] = bottom
            self
        end

        # Set the output page left margin.
        #
        # * +left+ - The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setMarginLeft(left)
            unless /(?i)^0$|^[0-9]*\.?[0-9]+(pt|px|mm|cm|in)$/.match(left)
                raise Error.new(Pdfcrowd.create_invalid_value_message(left, "setMarginLeft", "image-to-pdf", "The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.", "set_margin_left"), 470);
            end
            
            @fields['margin_left'] = left
            self
        end

        # Set the output page margins.
        #
        # * +top+ - Set the output page top margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +right+ - Set the output page right margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +bottom+ - Set the output page bottom margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * +left+ - Set the output page left margin. The value must be specified in inches 'in', millimeters 'mm', centimeters 'cm', pixels 'px', or points 'pt'.
        # * *Returns* - The converter object.
        def setPageMargins(top, right, bottom, left)
            setMarginTop(top)
            setMarginRight(right)
            setMarginBottom(bottom)
            setMarginLeft(left)
            self
        end

        # The page background color in RGB or RGBA hexadecimal format. The color fills the entire page regardless of the margins. If not page size is specified and the image format supports background (e.g. PDF, PNG), the background color is applied too.
        #
        # * +color+ - The value must be in RRGGBB or RRGGBBAA hexadecimal format.
        # * *Returns* - The converter object.
        def setPageBackgroundColor(color)
            unless /^[0-9a-fA-F]{6,8}$/.match(color)
                raise Error.new(Pdfcrowd.create_invalid_value_message(color, "setPageBackgroundColor", "image-to-pdf", "The value must be in RRGGBB or RRGGBBAA hexadecimal format.", "set_page_background_color"), 470);
            end
            
            @fields['page_background_color'] = color
            self
        end

        # Set the DPI resolution of the input image. The DPI affects margin options specified in points too (e.g. 1 point is equal to 1 pixel in 96 DPI).
        #
        # * +dpi+ - The DPI value.
        # * *Returns* - The converter object.
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # Apply a watermark to each page of the output PDF file. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setPageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_page_watermark"), 470);
            end
            
            @files['page_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply the file as a watermark to each page of the output PDF. A watermark can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the watermark.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_watermark_url"), 470);
            end
            
            @fields['page_watermark_url'] = url
            self
        end

        # Apply each page of a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +watermark+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageWatermark(watermark)
            if (!(File.file?(watermark) && !File.zero?(watermark)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(watermark, "setMultipageWatermark", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_watermark"), 470);
            end
            
            @files['multipage_watermark'] = watermark
            self
        end

        # Load a file from the specified URL and apply each page of the file as a watermark to the corresponding page of the output PDF. A watermark can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageWatermarkUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageWatermarkUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_watermark_url"), 470);
            end
            
            @fields['multipage_watermark_url'] = url
            self
        end

        # Apply a background to each page of the output PDF file. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setPageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setPageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_page_background"), 470);
            end
            
            @files['page_background'] = background
            self
        end

        # Load a file from the specified URL and apply the file as a background to each page of the output PDF. A background can be either a PDF or an image. If a multi-page file (PDF or TIFF) is used, the first page is used as the background.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setPageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setPageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_page_background_url"), 470);
            end
            
            @fields['page_background_url'] = url
            self
        end

        # Apply each page of a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +background+ - The file path to a local file. The file must exist and not be empty.
        # * *Returns* - The converter object.
        def setMultipageBackground(background)
            if (!(File.file?(background) && !File.zero?(background)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(background, "setMultipageBackground", "image-to-pdf", "The file must exist and not be empty.", "set_multipage_background"), 470);
            end
            
            @files['multipage_background'] = background
            self
        end

        # Load a file from the specified URL and apply each page of the file as a background to the corresponding page of the output PDF. A background can be either a PDF or an image.
        #
        # * +url+ - Supported protocols are http:// and https://.
        # * *Returns* - The converter object.
        def setMultipageBackgroundUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "setMultipageBackgroundUrl", "image-to-pdf", "Supported protocols are http:// and https://.", "set_multipage_background_url"), 470);
            end
            
            @fields['multipage_background_url'] = url
            self
        end

        # Create linearized PDF. This is also known as Fast Web View.
        #
        # * +value+ - Set to true to create linearized PDF.
        # * *Returns* - The converter object.
        def setLinearize(value)
            @fields['linearize'] = value
            self
        end

        # Encrypt the PDF. This prevents search engines from indexing the contents.
        #
        # * +value+ - Set to true to enable PDF encryption.
        # * *Returns* - The converter object.
        def setEncrypt(value)
            @fields['encrypt'] = value
            self
        end

        # Protect the PDF with a user password. When a PDF has a user password, it must be supplied in order to view the document and to perform operations allowed by the access permissions.
        #
        # * +password+ - The user password.
        # * *Returns* - The converter object.
        def setUserPassword(password)
            @fields['user_password'] = password
            self
        end

        # Protect the PDF with an owner password. Supplying an owner password grants unlimited access to the PDF including changing the passwords and access permissions.
        #
        # * +password+ - The owner password.
        # * *Returns* - The converter object.
        def setOwnerPassword(password)
            @fields['owner_password'] = password
            self
        end

        # Disallow printing of the output PDF.
        #
        # * +value+ - Set to true to set the no-print flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoPrint(value)
            @fields['no_print'] = value
            self
        end

        # Disallow modification of the output PDF.
        #
        # * +value+ - Set to true to set the read-only only flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoModify(value)
            @fields['no_modify'] = value
            self
        end

        # Disallow text and graphics extraction from the output PDF.
        #
        # * +value+ - Set to true to set the no-copy flag in the output PDF.
        # * *Returns* - The converter object.
        def setNoCopy(value)
            @fields['no_copy'] = value
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
        # * +layout+ - Allowed values are single-page, one-column, two-column-left, two-column-right.
        # * *Returns* - The converter object.
        def setPageLayout(layout)
            unless /(?i)^(single-page|one-column|two-column-left|two-column-right)$/.match(layout)
                raise Error.new(Pdfcrowd.create_invalid_value_message(layout, "setPageLayout", "image-to-pdf", "Allowed values are single-page, one-column, two-column-left, two-column-right.", "set_page_layout"), 470);
            end
            
            @fields['page_layout'] = layout
            self
        end

        # Specify how the document should be displayed when opened.
        #
        # * +mode+ - Allowed values are full-screen, thumbnails, outlines.
        # * *Returns* - The converter object.
        def setPageMode(mode)
            unless /(?i)^(full-screen|thumbnails|outlines)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageMode", "image-to-pdf", "Allowed values are full-screen, thumbnails, outlines.", "set_page_mode"), 470);
            end
            
            @fields['page_mode'] = mode
            self
        end

        # Specify how the page should be displayed when opened.
        #
        # * +zoom_type+ - Allowed values are fit-width, fit-height, fit-page.
        # * *Returns* - The converter object.
        def setInitialZoomType(zoom_type)
            unless /(?i)^(fit-width|fit-height|fit-page)$/.match(zoom_type)
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom_type, "setInitialZoomType", "image-to-pdf", "Allowed values are fit-width, fit-height, fit-page.", "set_initial_zoom_type"), 470);
            end
            
            @fields['initial_zoom_type'] = zoom_type
            self
        end

        # Display the specified page when the document is opened.
        #
        # * +page+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialPage(page)
            if (!(Integer(page) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(page, "setInitialPage", "image-to-pdf", "Must be a positive integer.", "set_initial_page"), 470);
            end
            
            @fields['initial_page'] = page
            self
        end

        # Specify the initial page zoom in percents when the document is opened.
        #
        # * +zoom+ - Must be a positive integer.
        # * *Returns* - The converter object.
        def setInitialZoom(zoom)
            if (!(Integer(zoom) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(zoom, "setInitialZoom", "image-to-pdf", "Must be a positive integer.", "set_initial_zoom"), 470);
            end
            
            @fields['initial_zoom'] = zoom
            self
        end

        # Specify whether to hide the viewer application's tool bars when the document is active.
        #
        # * +value+ - Set to true to hide tool bars.
        # * *Returns* - The converter object.
        def setHideToolbar(value)
            @fields['hide_toolbar'] = value
            self
        end

        # Specify whether to hide the viewer application's menu bar when the document is active.
        #
        # * +value+ - Set to true to hide the menu bar.
        # * *Returns* - The converter object.
        def setHideMenubar(value)
            @fields['hide_menubar'] = value
            self
        end

        # Specify whether to hide user interface elements in the document's window (such as scroll bars and navigation controls), leaving only the document's contents displayed.
        #
        # * +value+ - Set to true to hide ui elements.
        # * *Returns* - The converter object.
        def setHideWindowUi(value)
            @fields['hide_window_ui'] = value
            self
        end

        # Specify whether to resize the document's window to fit the size of the first displayed page.
        #
        # * +value+ - Set to true to resize the window.
        # * *Returns* - The converter object.
        def setFitWindow(value)
            @fields['fit_window'] = value
            self
        end

        # Specify whether to position the document's window in the center of the screen.
        #
        # * +value+ - Set to true to center the window.
        # * *Returns* - The converter object.
        def setCenterWindow(value)
            @fields['center_window'] = value
            self
        end

        # Specify whether the window's title bar should display the document title. If false , the title bar should instead display the name of the PDF file containing the document.
        #
        # * +value+ - Set to true to display the title.
        # * *Returns* - The converter object.
        def setDisplayTitle(value)
            @fields['display_title'] = value
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "image-to-pdf", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "image-to-pdf", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to HTML.
    class PdfToHtmlClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
        # * +api_key+ - Your API key.
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

        # Convert a PDF.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a PDF and write the result to an output stream.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-html", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a PDF and write the result to a local file.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-html", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-html", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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
        # * +file_path+ - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data.
        # * +file_path+ - The output file path. The string must not be empty. The converter generates an HTML or ZIP file. If ZIP file is generated, the file path must have a ZIP or zip extension.
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

        # Password to open the encrypted PDF file.
        #
        # * +password+ - The input PDF password.
        # * *Returns* - The converter object.
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # Set the scaling factor (zoom) for the main page area.
        #
        # * +factor+ - The percentage value. Must be a positive integer.
        # * *Returns* - The converter object.
        def setScaleFactor(factor)
            if (!(Integer(factor) > 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(factor, "setScaleFactor", "pdf-to-html", "Must be a positive integer.", "set_scale_factor"), 470);
            end
            
            @fields['scale_factor'] = factor
            self
        end

        # Set the page range to print.
        #
        # * +pages+ - A comma separated list of page numbers or ranges.
        # * *Returns* - The converter object.
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-html", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # Set the output graphics DPI.
        #
        # * +dpi+ - The DPI value.
        # * *Returns* - The converter object.
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # Specifies where the images are stored.
        #
        # * +mode+ - The image storage mode. Allowed values are embed, separate, none.
        # * *Returns* - The converter object.
        def setImageMode(mode)
            unless /(?i)^(embed|separate|none)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setImageMode", "pdf-to-html", "Allowed values are embed, separate, none.", "set_image_mode"), 470);
            end
            
            @fields['image_mode'] = mode
            self
        end

        # Specifies the format for the output images.
        #
        # * +image_format+ - The image format. Allowed values are png, jpg, svg.
        # * *Returns* - The converter object.
        def setImageFormat(image_format)
            unless /(?i)^(png|jpg|svg)$/.match(image_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(image_format, "setImageFormat", "pdf-to-html", "Allowed values are png, jpg, svg.", "set_image_format"), 470);
            end
            
            @fields['image_format'] = image_format
            self
        end

        # Specifies where the style sheets are stored.
        #
        # * +mode+ - The style sheet storage mode. Allowed values are embed, separate.
        # * *Returns* - The converter object.
        def setCssMode(mode)
            unless /(?i)^(embed|separate)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setCssMode", "pdf-to-html", "Allowed values are embed, separate.", "set_css_mode"), 470);
            end
            
            @fields['css_mode'] = mode
            self
        end

        # Specifies where the fonts are stored.
        #
        # * +mode+ - The font storage mode. Allowed values are embed, separate.
        # * *Returns* - The converter object.
        def setFontMode(mode)
            unless /(?i)^(embed|separate)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setFontMode", "pdf-to-html", "Allowed values are embed, separate.", "set_font_mode"), 470);
            end
            
            @fields['font_mode'] = mode
            self
        end

        # Sets the processing mode for handling Type 3 fonts.
        #
        # * +mode+ - The type3 font mode. Allowed values are raster, convert.
        # * *Returns* - The converter object.
        def setType3Mode(mode)
            unless /(?i)^(raster|convert)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setType3Mode", "pdf-to-html", "Allowed values are raster, convert.", "set_type3_mode"), 470);
            end
            
            @fields['type3_mode'] = mode
            self
        end

        # Converts ligatures, two or more letters combined into a single glyph, back into their individual ASCII characters.
        #
        # * +value+ - Set to true to split ligatures.
        # * *Returns* - The converter object.
        def setSplitLigatures(value)
            @fields['split_ligatures'] = value
            self
        end

        # Apply custom CSS to the output HTML document. It allows you to modify the visual appearance and layout. Tip: Using !important in custom CSS provides a way to prioritize and override conflicting styles.
        #
        # * +css+ - A string containing valid CSS. The string must not be empty.
        # * *Returns* - The converter object.
        def setCustomCss(css)
            if (!(!css.nil? && !css.empty?))
                raise Error.new(Pdfcrowd.create_invalid_value_message(css, "setCustomCss", "pdf-to-html", "The string must not be empty.", "set_custom_css"), 470);
            end
            
            @fields['custom_css'] = css
            self
        end

        # Add the specified prefix to all id and class attributes in the HTML content, creating a namespace for safe integration into another HTML document. This ensures unique identifiers, preventing conflicts when merging with other HTML.
        #
        # * +prefix+ - The prefix to add before each id and class attribute name. Start with a letter or underscore, and use only letters, numbers, hyphens, underscores, or colons.
        # * *Returns* - The converter object.
        def setHtmlNamespace(prefix)
            unless /(?i)^[a-z_][a-z0-9_:-]*$/.match(prefix)
                raise Error.new(Pdfcrowd.create_invalid_value_message(prefix, "setHtmlNamespace", "pdf-to-html", "Start with a letter or underscore, and use only letters, numbers, hyphens, underscores, or colons.", "set_html_namespace"), 470);
            end
            
            @fields['html_namespace'] = prefix
            self
        end

        # A helper method to determine if the output file is a zip archive. The output of the conversion may be either an HTML file or a zip file containing the HTML and its external assets.
        # * *Returns* - True if the conversion output is a zip file, otherwise False.
        def isZippedOutput()
            @fields.fetch('image_mode', '') == 'separate' || @fields.fetch('css_mode', '') == 'separate' || @fields.fetch('font_mode', '') == 'separate' || @fields.fetch('force_zip', false) == true
        end

        # Enforces the zip output format.
        #
        # * +value+ - Set to true to get the output as a zip archive.
        # * *Returns* - The converter object.
        def setForceZip(value)
            @fields['force_zip'] = value
            self
        end

        # Set the HTML title. The title from the input PDF is used by default.
        #
        # * +title+ - The HTML title.
        # * *Returns* - The converter object.
        def setTitle(title)
            @fields['title'] = title
            self
        end

        # Set the HTML subject. The subject from the input PDF is used by default.
        #
        # * +subject+ - The HTML subject.
        # * *Returns* - The converter object.
        def setSubject(subject)
            @fields['subject'] = subject
            self
        end

        # Set the HTML author. The author from the input PDF is used by default.
        #
        # * +author+ - The HTML author.
        # * *Returns* - The converter object.
        def setAuthor(author)
            @fields['author'] = author
            self
        end

        # Associate keywords with the HTML document. Keywords from the input PDF are used by default.
        #
        # * +keywords+ - The string containing the keywords.
        # * *Returns* - The converter object.
        def setKeywords(keywords)
            @fields['keywords'] = keywords
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-html", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # Set the converter version. Different versions may produce different output. Choose which one provides the best output for your case.
        #
        # * +version+ - The version identifier. Allowed values are 24.04, 20.10, 18.10, latest.
        # * *Returns* - The converter object.
        def setConverterVersion(version)
            unless /(?i)^(24.04|20.10|18.10|latest)$/.match(version)
                raise Error.new(Pdfcrowd.create_invalid_value_message(version, "setConverterVersion", "pdf-to-html", "Allowed values are 24.04, 20.10, 18.10, latest.", "set_converter_version"), 470);
            end
            
            @helper.setConverterVersion(version)
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
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
    class PdfToTextClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
        # * +api_key+ - Your API key.
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

        # Convert a PDF.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a PDF and write the result to an output stream.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-text", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a PDF and write the result to a local file.
        #
        # * +url+ - The address of the PDF to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-text", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-text", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # The password to open the encrypted PDF file.
        #
        # * +password+ - The input PDF password.
        # * *Returns* - The converter object.
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # Set the page range to print.
        #
        # * +pages+ - A comma separated list of page numbers or ranges.
        # * *Returns* - The converter object.
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-text", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # Ignore the original PDF layout.
        #
        # * +value+ - Set to true to ignore the layout.
        # * *Returns* - The converter object.
        def setNoLayout(value)
            @fields['no_layout'] = value
            self
        end

        # The end-of-line convention for the text output.
        #
        # * +eol+ - Allowed values are unix, dos, mac.
        # * *Returns* - The converter object.
        def setEol(eol)
            unless /(?i)^(unix|dos|mac)$/.match(eol)
                raise Error.new(Pdfcrowd.create_invalid_value_message(eol, "setEol", "pdf-to-text", "Allowed values are unix, dos, mac.", "set_eol"), 470);
            end
            
            @fields['eol'] = eol
            self
        end

        # Specify the page break mode for the text output.
        #
        # * +mode+ - Allowed values are none, default, custom.
        # * *Returns* - The converter object.
        def setPageBreakMode(mode)
            unless /(?i)^(none|default|custom)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setPageBreakMode", "pdf-to-text", "Allowed values are none, default, custom.", "set_page_break_mode"), 470);
            end
            
            @fields['page_break_mode'] = mode
            self
        end

        # Specify the custom page break.
        #
        # * +page_break+ - String to insert between the pages.
        # * *Returns* - The converter object.
        def setCustomPageBreak(page_break)
            @fields['custom_page_break'] = page_break
            self
        end

        # Specify the paragraph detection mode.
        #
        # * +mode+ - Allowed values are none, bounding-box, characters.
        # * *Returns* - The converter object.
        def setParagraphMode(mode)
            unless /(?i)^(none|bounding-box|characters)$/.match(mode)
                raise Error.new(Pdfcrowd.create_invalid_value_message(mode, "setParagraphMode", "pdf-to-text", "Allowed values are none, bounding-box, characters.", "set_paragraph_mode"), 470);
            end
            
            @fields['paragraph_mode'] = mode
            self
        end

        # Set the maximum line spacing when the paragraph detection mode is enabled.
        #
        # * +threshold+ - The value must be a positive integer percentage.
        # * *Returns* - The converter object.
        def setLineSpacingThreshold(threshold)
            unless /(?i)^0$|^[0-9]+%$/.match(threshold)
                raise Error.new(Pdfcrowd.create_invalid_value_message(threshold, "setLineSpacingThreshold", "pdf-to-text", "The value must be a positive integer percentage.", "set_line_spacing_threshold"), 470);
            end
            
            @fields['line_spacing_threshold'] = threshold
            self
        end

        # Remove the hyphen character from the end of lines.
        #
        # * +value+ - Set to true to remove hyphens.
        # * *Returns* - The converter object.
        def setRemoveHyphenation(value)
            @fields['remove_hyphenation'] = value
            self
        end

        # Remove empty lines from the text output.
        #
        # * +value+ - Set to true to remove empty lines.
        # * *Returns* - The converter object.
        def setRemoveEmptyLines(value)
            @fields['remove_empty_lines'] = value
            self
        end

        # Set the top left X coordinate of the crop area in points.
        #
        # * +x+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaX(x)
            if (!(Integer(x) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # Set the top left Y coordinate of the crop area in points.
        #
        # * +y+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaY(y)
            if (!(Integer(y) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # Set the width of the crop area in points.
        #
        # * +width+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaWidth(width)
            if (!(Integer(width) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # Set the height of the crop area in points.
        #
        # * +height+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaHeight(height)
            if (!(Integer(height) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "pdf-to-text", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # Set the crop area. It allows to extract just a part of a PDF page.
        #
        # * +x+ - Set the top left X coordinate of the crop area in points. Must be a positive integer or 0.
        # * +y+ - Set the top left Y coordinate of the crop area in points. Must be a positive integer or 0.
        # * +width+ - Set the width of the crop area in points. Must be a positive integer or 0.
        # * +height+ - Set the height of the crop area in points. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-text", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

    # Conversion from PDF to image.
    class PdfToImageClient
        # Constructor for the PDFCrowd API client.
        #
        # * +user_name+ - Your username at PDFCrowd.
        # * +api_key+ - Your API key.
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

        # Convert an image.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * *Returns* - Byte array containing the conversion output.
        def convertUrl(url)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrl", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert an image and write the result to an output stream.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertUrlToStream(url, out_stream)
            unless /(?i)^https?:\/\/.*$/.match(url)
                raise Error.new(Pdfcrowd.create_invalid_value_message(url, "convertUrlToStream::url", "pdf-to-image", "Supported protocols are http:// and https://.", "convert_url_to_stream"), 470);
            end
            
            @fields['url'] = url
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert an image and write the result to a local file.
        #
        # * +url+ - The address of the image to convert. Supported protocols are http:// and https://.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * *Returns* - Byte array containing the conversion output.
        def convertFile(file)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFile", "pdf-to-image", "The file must exist and not be empty.", "convert_file"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert a local file and write the result to an output stream.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertFileToStream(file, out_stream)
            if (!(File.file?(file) && !File.zero?(file)))
                raise Error.new(Pdfcrowd.create_invalid_value_message(file, "convertFileToStream::file", "pdf-to-image", "The file must exist and not be empty.", "convert_file_to_stream"), 470);
            end
            
            @files['file'] = file
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert a local file and write the result to a local file.
        #
        # * +file+ - The path to a local file to convert. The file must exist and not be empty.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # Convert the contents of an input stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * *Returns* - Byte array containing the conversion output.
        def convertStream(in_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data)
        end

        # Convert the contents of an input stream and write the result to an output stream.
        #
        # * +in_stream+ - The input stream with source data.
        # * +out_stream+ - The output stream that will contain the conversion output.
        def convertStreamToStream(in_stream, out_stream)
            @raw_data['stream'] = in_stream.read
            @helper.post(@fields, @files, @raw_data, out_stream)
        end

        # Convert the contents of an input stream and write the result to a local file.
        #
        # * +in_stream+ - The input stream with source data.
        # * +file_path+ - The output file path. The string must not be empty.
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

        # The format of the output file.
        #
        # * +output_format+ - Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.
        # * *Returns* - The converter object.
        def setOutputFormat(output_format)
            unless /(?i)^(png|jpg|gif|tiff|bmp|ico|ppm|pgm|pbm|pnm|psb|pct|ras|tga|sgi|sun|webp)$/.match(output_format)
                raise Error.new(Pdfcrowd.create_invalid_value_message(output_format, "setOutputFormat", "pdf-to-image", "Allowed values are png, jpg, gif, tiff, bmp, ico, ppm, pgm, pbm, pnm, psb, pct, ras, tga, sgi, sun, webp.", "set_output_format"), 470);
            end
            
            @fields['output_format'] = output_format
            self
        end

        # Password to open the encrypted PDF file.
        #
        # * +password+ - The input PDF password.
        # * *Returns* - The converter object.
        def setPdfPassword(password)
            @fields['pdf_password'] = password
            self
        end

        # Set the page range to print.
        #
        # * +pages+ - A comma separated list of page numbers or ranges.
        # * *Returns* - The converter object.
        def setPrintPageRange(pages)
            unless /^(?:\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*,\s*)*\s*(?:\d+|(?:\d*\s*\-\s*\d+)|(?:\d+\s*\-\s*\d*))\s*$/.match(pages)
                raise Error.new(Pdfcrowd.create_invalid_value_message(pages, "setPrintPageRange", "pdf-to-image", "A comma separated list of page numbers or ranges.", "set_print_page_range"), 470);
            end
            
            @fields['print_page_range'] = pages
            self
        end

        # Set the output graphics DPI.
        #
        # * +dpi+ - The DPI value.
        # * *Returns* - The converter object.
        def setDpi(dpi)
            @fields['dpi'] = dpi
            self
        end

        # A helper method to determine if the output file from a conversion process is a zip archive. The conversion output can be either a single image file or a zip file containing one or more image files. This method should be called after the conversion has been successfully completed.
        # * *Returns* - True if the conversion output is a zip archive, otherwise False.
        def isZippedOutput()
            @fields.fetch('force_zip', false) == true || getPageCount() > 1
        end

        # Enforces the zip output format.
        #
        # * +value+ - Set to true to get the output as a zip archive.
        # * *Returns* - The converter object.
        def setForceZip(value)
            @fields['force_zip'] = value
            self
        end

        # Use the crop box rather than media box.
        #
        # * +value+ - Set to true to use crop box.
        # * *Returns* - The converter object.
        def setUseCropbox(value)
            @fields['use_cropbox'] = value
            self
        end

        # Set the top left X coordinate of the crop area in points.
        #
        # * +x+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaX(x)
            if (!(Integer(x) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(x, "setCropAreaX", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_x"), 470);
            end
            
            @fields['crop_area_x'] = x
            self
        end

        # Set the top left Y coordinate of the crop area in points.
        #
        # * +y+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaY(y)
            if (!(Integer(y) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(y, "setCropAreaY", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_y"), 470);
            end
            
            @fields['crop_area_y'] = y
            self
        end

        # Set the width of the crop area in points.
        #
        # * +width+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaWidth(width)
            if (!(Integer(width) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(width, "setCropAreaWidth", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_width"), 470);
            end
            
            @fields['crop_area_width'] = width
            self
        end

        # Set the height of the crop area in points.
        #
        # * +height+ - Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropAreaHeight(height)
            if (!(Integer(height) >= 0))
                raise Error.new(Pdfcrowd.create_invalid_value_message(height, "setCropAreaHeight", "pdf-to-image", "Must be a positive integer or 0.", "set_crop_area_height"), 470);
            end
            
            @fields['crop_area_height'] = height
            self
        end

        # Set the crop area. It allows to extract just a part of a PDF page.
        #
        # * +x+ - Set the top left X coordinate of the crop area in points. Must be a positive integer or 0.
        # * +y+ - Set the top left Y coordinate of the crop area in points. Must be a positive integer or 0.
        # * +width+ - Set the width of the crop area in points. Must be a positive integer or 0.
        # * +height+ - Set the height of the crop area in points. Must be a positive integer or 0.
        # * *Returns* - The converter object.
        def setCropArea(x, y, width, height)
            setCropAreaX(x)
            setCropAreaY(y)
            setCropAreaWidth(width)
            setCropAreaHeight(height)
            self
        end

        # Generate a grayscale image.
        #
        # * +value+ - Set to true to generate a grayscale image.
        # * *Returns* - The converter object.
        def setUseGrayscale(value)
            @fields['use_grayscale'] = value
            self
        end

        # Turn on the debug logging. Details about the conversion are stored in the debug log. The URL of the log can be obtained from the getDebugLogUrl method or available in conversion statistics.
        #
        # * +value+ - Set to true to enable the debug logging.
        # * *Returns* - The converter object.
        def setDebugLog(value)
            @fields['debug_log'] = value
            self
        end

        # Get the URL of the debug log for the last conversion.
        # * *Returns* - The link to the debug log.
        def getDebugLogUrl()
            return @helper.getDebugLogUrl()
        end

        # Get the number of conversion credits available in your account.
        # This method can only be called after a call to one of the convertXtoY methods.
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

        # Get the number of pages in the output document.
        # * *Returns* - The page count.
        def getPageCount()
            return @helper.getPageCount()
        end

        # Get the size of the output in bytes.
        # * *Returns* - The count of bytes.
        def getOutputSize()
            return @helper.getOutputSize()
        end

        # Get the version details.
        # * *Returns* - API version, converter version, and client version.
        def getVersion()
            return "client " + CLIENT_VERSION + ", API v2, converter " + @helper.getConverterVersion()
        end

        # Tag the conversion with a custom value. The tag is used in conversion statistics. A value longer than 32 characters is cut off.
        #
        # * +tag+ - A string with the custom tag.
        # * *Returns* - The converter object.
        def setTag(tag)
            @fields['tag'] = tag
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTP scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_http_proxy"), 470);
            end
            
            @fields['http_proxy'] = proxy
            self
        end

        # A proxy server used by the conversion process for accessing the source URLs with HTTPS scheme. It can help to circumvent regional restrictions or provide limited access to your intranet.
        #
        # * +proxy+ - The value must have format DOMAIN_OR_IP_ADDRESS:PORT.
        # * *Returns* - The converter object.
        def setHttpsProxy(proxy)
            unless /(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z0-9]{1,}:\d+$/.match(proxy)
                raise Error.new(Pdfcrowd.create_invalid_value_message(proxy, "setHttpsProxy", "pdf-to-image", "The value must have format DOMAIN_OR_IP_ADDRESS:PORT.", "set_https_proxy"), 470);
            end
            
            @fields['https_proxy'] = proxy
            self
        end

        # Specify whether to use HTTP or HTTPS when connecting to the PDFCrowd API.
        # Warning: Using HTTP is insecure as data sent over HTTP is not encrypted. Enable this option only if you know what you are doing.
        #
        # * +value+ - Set to true to use HTTP.
        # * *Returns* - The converter object.
        def setUseHttp(value)
            @helper.setUseHttp(value)
            self
        end

        # Specifies the User-Agent HTTP header that the client library will use when interacting with the API.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setClientUserAgent(agent)
            @helper.setUserAgent(agent)
            self
        end

        # Set a custom user agent HTTP header. It can be useful if you are behind a proxy or a firewall.
        #
        # * +agent+ - The user agent string.
        # * *Returns* - The converter object.
        def setUserAgent(agent)
            @helper.setUserAgent(agent)
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

        # Specifies the number of automatic retries when the 502 or 503 HTTP status code is received. The status code indicates a temporary network issue. This feature can be disabled by setting to 0.
        #
        # * +count+ - Number of retries.
        # * *Returns* - The converter object.
        def setRetryCount(count)
            @helper.setRetryCount(count)
            self
        end

    end

end
