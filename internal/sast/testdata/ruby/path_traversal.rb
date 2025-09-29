# Path Traversal Test Cases

class PathTraversalController < ApplicationController
  def file_read
    filename = params[:file]
    
    # Direct path traversal vulnerabilities
    File.read(filename)  # VULNERABLE
    File.open(filename)  # VULNERABLE
    IO.read(filename)  # VULNERABLE
    
    # File operations with user input
    File.exists?(filename)  # INFORMATION DISCLOSURE
    File.directory?(filename)  # INFORMATION DISCLOSURE
    File.size(filename)  # INFORMATION DISCLOSURE
  end

  def file_write
    filename = params[:filename]
    content = params[:content]
    
    # Path traversal in write operations
    File.write(filename, content)  # VULNERABLE
    File.open(filename, 'w') { |f| f.write(content) }  # VULNERABLE
    
    # Directory operations
    Dir.mkdir(filename)  # VULNERABLE
    FileUtils.mkdir_p(filename)  # VULNERABLE
  end

  def send_file_vulnerabilities
    file_path = params[:path]
    
    # Rails send_file with user input
    send_file(file_path)  # VULNERABLE
    send_data(File.read(file_path), filename: "download.txt")  # VULNERABLE
  end

  def zip_operations
    zip_file = params[:zip_file]
    extract_path = params[:extract_to]
    
    # Zip slip vulnerability
    Zip::File.open(zip_file) do |zip|
      zip.each do |entry|
        # No path validation - zip slip vulnerability
        entry.extract(File.join(extract_path, entry.name))  # VULNERABLE
      end
    end
  end

  def safe_file_operations
    filename = params[:file]
    
    # Safe - path validation
    safe_filename = File.basename(filename)
    safe_path = File.join("/safe/directory", safe_filename)
    
    # Ensure path is within allowed directory
    if File.expand_path(safe_path).start_with?("/safe/directory")
      File.read(safe_path)  # SAFE
    end
  end

  def template_path_traversal
    template_name = params[:template]
    
    # Template path traversal
    render template: template_name  # VULNERABLE
    render partial: template_name  # VULNERABLE
    render file: template_name  # VULNERABLE
  end

  def include_require_traversal
    lib_name = params[:lib]
    
    # Dynamic require/load with user input
    require lib_name  # VULNERABLE
    load "#{lib_name}.rb"  # VULNERABLE
    autoload :MyClass, lib_name  # VULNERABLE
  end
end

# File upload vulnerabilities
class FileUploadController < ApplicationController
  def upload
    uploaded_file = params[:file]
    
    # Unsafe file upload - no path validation
    filename = uploaded_file.original_filename
    File.open(File.join("uploads", filename), "wb") do |f|  # VULNERABLE
      f.write(uploaded_file.read)
    end
  end

  def safe_upload
    uploaded_file = params[:file]
    
    # Safe file upload with validation
    filename = File.basename(uploaded_file.original_filename)
    allowed_dir = Rails.root.join("uploads")
    safe_path = allowed_dir.join(filename)
    
    # Validate path is within allowed directory
    if safe_path.to_s.start_with?(allowed_dir.to_s)
      File.open(safe_path, "wb") do |f|  # SAFE
        f.write(uploaded_file.read)
      end
    end
  end
end

# Directory traversal in various contexts
class DirectoryTraversalExamples
  def self.log_file_access
    log_name = ENV['LOG_FILE'] || "app.log"
    
    # Environment variable path traversal
    File.open("/var/log/#{log_name}")  # VULNERABLE if LOG_FILE is controlled by attacker
  end

  def self.config_file_read
    config_name = ARGV[0]
    
    # Command line argument path traversal
    YAML.load_file("config/#{config_name}.yml")  # VULNERABLE
  end

  def self.gem_path_traversal
    gem_name = params[:gem]
    
    # Gem loading with user input
    Gem.loaded_specs[gem_name]&.load_paths&.each do |path|
      Dir.glob("#{path}/**/*.rb").each { |file| require file }  # VULNERABLE
    end
  end
end

# Symlink attacks
class SymlinkController < ApplicationController
  def read_symlink
    file_path = params[:path]
    
    # Following symlinks can lead to path traversal
    real_path = File.realpath(file_path)  # Can follow symlinks outside allowed directory
    File.read(real_path)  # VULNERABLE
  end

  def safe_symlink_handling
    file_path = params[:path]
    allowed_dir = "/safe/directory"
    
    # Safe symlink handling
    real_path = File.realpath(file_path)
    if real_path.start_with?(File.realpath(allowed_dir))
      File.read(real_path)  # SAFE
    else
      raise "Path not allowed"
    end
  end
end