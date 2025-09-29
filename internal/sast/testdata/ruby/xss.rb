# Cross-Site Scripting (XSS) Test Cases

class XssController < ApplicationController
  def erb_injection
    user_input = params[:content]
    
    # ERB template injection
    @content = user_input
    render inline: "<%= @content %>"  # VULNERABLE
    render inline: "<%= #{user_input} %>"  # VULNERABLE
    
    # Dynamic ERB compilation
    template = ERB.new("<h1><%= user_data %></h1>")
    template.result(binding)  # VULNERABLE if user_data is tainted
  end

  def html_output
    name = params[:name]
    message = params[:message]
    
    # Direct HTML output without sanitization
    render html: "<h1>Hello #{name}</h1>".html_safe  # VULNERABLE
    render text: "Message: #{message}"  # VULNERABLE (in older Rails)
    
    # String concatenation leading to XSS
    output = "<div>" + message + "</div>"
    render html: output.html_safe  # VULNERABLE
  end

  def json_xss
    callback = params[:callback]
    data = { status: "success" }
    
    # JSONP callback injection
    render json: data, callback: callback  # VULNERABLE
    render text: "#{callback}(#{data.to_json})"  # VULNERABLE
  end

  def safe_output
    user_input = params[:input]
    
    # Safe - proper escaping
    render html: html_escape(user_input)  # SAFE
    render html: h(user_input)  # SAFE
    
    # Safe - auto-escaping in ERB
    @safe_content = user_input
    render template: "safe_template"  # SAFE if template uses <%= %> with auto-escaping
  end

  def javascript_injection
    user_data = params[:data]
    
    # JavaScript injection in script tags
    render inline: "<script>var data = '#{user_data}';</script>"  # VULNERABLE
    
    # JavaScript injection in data attributes
    render inline: "<div data-value='#{user_data}'>Content</div>"  # VULNERABLE
  end

  def css_injection
    user_color = params[:color]
    
    # CSS injection
    render inline: "<style>body { color: #{user_color}; }</style>"  # VULNERABLE
  end
end

# Helper methods that can lead to XSS
module ApplicationHelper
  def unsafe_format(text)
    # Vulnerable helper method
    "<p>#{text}</p>".html_safe  # VULNERABLE
  end

  def safe_format(text)
    # Safe helper method
    content_tag(:p, text)  # SAFE - content_tag escapes by default
  end

  def dynamic_link(url, text)
    # URL injection
    link_to text, url  # POTENTIALLY VULNERABLE if url is javascript: or data:
  end
end

# Haml template injection
class HamlController < ApplicationController
  def haml_injection
    user_content = params[:content]
    
    # Haml injection patterns
    render haml: "= #{user_content}"  # VULNERABLE
    render haml: "%div= user_input"  # VULNERABLE if user_input is tainted
  end
end

# ActionMailer XSS
class UserMailer < ActionMailer::Base
  def notification(user_message)
    @message = user_message  # VULNERABLE if used unescaped in template
    mail(to: "user@example.com", subject: "Notification")
  end
end

# Background job XSS (if jobs generate HTML)
class HtmlGeneratorWorker
  include Sidekiq::Worker
  
  def perform(user_content)
    # Generating HTML in background job
    html = "<div>#{user_content}</div>"  # VULNERABLE
    File.write("output.html", html)
  end
end

# XML injection
class XmlController < ApplicationController
  def xml_output
    user_data = params[:data]
    
    # XML injection
    render xml: "<root><data>#{user_data}</data></root>"  # VULNERABLE
    
    # Builder XML with interpolation
    xml = Builder::XmlMarkup.new
    xml.root do
      xml.data user_data  # POTENTIALLY VULNERABLE depending on Builder version
    end
    render xml: xml.target!
  end
end