# Command Injection Test Cases

class CommandInjectionController < ApplicationController
  def vulnerable_system
    # Direct command injection
    user_input = params[:cmd]
    system("ls #{user_input}")  # VULNERABLE
    `grep #{user_input} /etc/passwd`  # VULNERABLE
    %x(ps aux | grep #{user_input})  # VULNERABLE
  end

  def kernel_methods
    cmd = params[:command]
    Kernel.system(cmd)  # VULNERABLE
    exec(cmd)  # VULNERABLE
    spawn(cmd)  # VULNERABLE
    IO.popen(cmd)  # VULNERABLE
  end

  def sanitized_safe
    user_input = params[:search]
    # Safe - proper sanitization
    safe_input = Shellwords.escape(user_input)
    system("grep #{safe_input} logfile.txt")  # SAFE
  end

  def array_safe
    # Safe - array form prevents shell injection
    user_file = params[:file]
    system("cat", user_file)  # SAFE
  end

  def subprocess_vulnerable
    require 'subprocess'
    cmd = params[:cmd]
    
    # Various subprocess patterns
    Subprocess.check_call(["/bin/sh", "-c", cmd])  # VULNERABLE if cmd is tainted
    Process.spawn(cmd)  # VULNERABLE
    Open3.capture2(cmd)  # VULNERABLE
  end

  def file_operations
    filename = params[:file]
    
    # File operations that can lead to command injection
    File.open("|cat #{filename}")  # VULNERABLE - pipe open
    IO.foreach("|ls #{filename}")  # VULNERABLE
  end
end

# Background job command injection
class VulnerableWorker
  include Sidekiq::Worker
  
  def perform(user_command)
    # Command injection in background job
    system(user_command)  # VULNERABLE
  end
end

# Library/gem specific patterns
module SystemUtils
  def self.run_command(cmd)
    # Utility method that could be misused
    %x(#{cmd})  # VULNERABLE
  end
  
  def self.safe_run(cmd, *args)
    # Safe version
    system(cmd, *args)  # SAFE
  end
end