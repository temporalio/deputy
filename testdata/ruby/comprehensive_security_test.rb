class ComprehensiveSecurityController < ApplicationController
  # Command injection vulnerability
  def command_injection
    user_input = params[:cmd]
    system("ls #{user_input}")  # Vulnerable to command injection
  end

  # SQL injection vulnerability
  def sql_injection
    user_id = params[:id]
    User.find_by_sql("SELECT * FROM users WHERE id = #{user_id}")  # Vulnerable to SQL injection
  end

  # XSS vulnerability
  def xss_vulnerability
    message = params[:message]
    render plain: message.html_safe  # Vulnerable to XSS
  end

  # Path traversal vulnerability
  def path_traversal
    filename = params[:file]
    File.read("/uploads/#{filename}")  # Vulnerable to path traversal
  end

  # Code injection vulnerability
  def code_injection
    code = params[:code]
    eval(code)  # Vulnerable to code injection
  end

  # Deserialization vulnerability
  def deserialization
    data = params[:data]
    Marshal.load(data)  # Vulnerable to deserialization attacks
  end

  # Complex taint flow with sanitization
  def complex_flow
    user_input = params[:data]
    sanitized = sanitize_input(user_input)  # Sanitizer should stop taint
    system("echo #{sanitized}")  # Should not be flagged as vulnerable
  end

  private

  def sanitize_input(input)
    input.gsub(/[^a-zA-Z0-9]/, '')
  end
end

# Multiple vulnerability patterns in one method
class MultiVulnController < ApplicationController
  def dangerous_method
    user_data = params[:data]
    
    # Multiple sinks in sequence
    system("cat #{user_data}")  # Command injection
    User.find_by_sql("SELECT * FROM users WHERE name = '#{user_data}'")  # SQL injection
    render plain: user_data.html_safe  # XSS
  end
end

# Test taint sources beyond params
class TaintSourceController < ApplicationController
  def test_sources
    # Different taint sources
    cookie_data = cookies[:data]
    session_data = session[:user_id]
    env_data = ENV['USER_INPUT']
    
    system("echo #{cookie_data}")
    User.find_by_sql("SELECT * FROM users WHERE id = #{session_data}")
    File.read(env_data)
  end
end