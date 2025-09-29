# Code Injection Test Cases

class CodeInjectionController < ApplicationController
  def eval_injection
    user_code = params[:code]
    user_expression = params[:expr]
    
    # Direct eval with user input
    eval(user_code)  # VULNERABLE
    eval("result = #{user_expression}")  # VULNERABLE
    
    # Instance and class eval
    instance_eval(user_code)  # VULNERABLE
    class_eval(user_code)  # VULNERABLE
    module_eval(user_code)  # VULNERABLE
  end

  def dynamic_method_access
    method_name = params[:method]
    class_name = params[:class]
    constant_name = params[:constant]
    
    # Dynamic method calls
    send(method_name)  # VULNERABLE
    public_send(method_name)  # VULNERABLE
    __send__(method_name)  # VULNERABLE
    
    # Dynamic constant access
    Object.const_get(class_name)  # VULNERABLE
    const_get(constant_name)  # VULNERABLE
    
    # Dynamic class instantiation
    Object.const_get(class_name).new  # VULNERABLE
  end

  def reflection_injection
    attribute_name = params[:attr]
    
    # Dynamic attribute access
    instance_variable_get("@#{attribute_name}")  # VULNERABLE
    instance_variable_set("@#{attribute_name}", "value")  # VULNERABLE
    
    # Dynamic method definition
    define_method(attribute_name) { "value" }  # VULNERABLE
    define_singleton_method(attribute_name) { "value" }  # VULNERABLE
  end

  def yaml_deserialization
    yaml_data = params[:data]
    
    # Unsafe YAML deserialization
    YAML.load(yaml_data)  # VULNERABLE - can execute arbitrary code
    YAML.unsafe_load(yaml_data)  # VULNERABLE - explicitly unsafe
    
    # Psych YAML parser
    Psych.load(yaml_data)  # VULNERABLE
    Psych.unsafe_load(yaml_data)  # VULNERABLE
  end

  def marshal_deserialization
    marshal_data = params[:data]
    
    # Unsafe Marshal deserialization
    Marshal.load(marshal_data)  # VULNERABLE - can execute arbitrary code
    Marshal.restore(marshal_data)  # VULNERABLE
  end

  def json_deserialization
    json_data = params[:data]
    
    # JSON deserialization with unsafe options
    JSON.parse(json_data, create_additions: true)  # VULNERABLE - can instantiate arbitrary classes
    JSON.load(json_data)  # VULNERABLE - deprecated and unsafe
  end

  def safe_deserialization
    yaml_data = params[:data]
    json_data = params[:json]
    
    # Safe YAML loading
    YAML.safe_load(yaml_data)  # SAFE
    YAML.safe_load(yaml_data, permitted_classes: [Date, Time])  # SAFE with allowlist
    
    # Safe JSON parsing
    JSON.parse(json_data)  # SAFE - default options
  end

  def template_injection
    template_string = params[:template]
    
    # ERB template injection
    ERB.new(template_string).result  # VULNERABLE
    ERB.new(template_string).result(binding)  # VULNERABLE
    
    # Liquid template injection (if using Liquid)
    Liquid::Template.parse(template_string).render  # POTENTIALLY VULNERABLE
  end

  def proc_creation
    code_string = params[:code]
    
    # Creating Proc objects from user input
    proc = Proc.new { eval(code_string) }  # VULNERABLE
    lambda_proc = lambda { eval(code_string) }  # VULNERABLE
    proc.call
  end
end

# Background job code injection
class CodeExecutionWorker
  include Sidekiq::Worker
  
  def perform(user_code)
    # Code injection in background job
    eval(user_code)  # VULNERABLE
  end
end

# Metaprogramming vulnerabilities
class MetaprogrammingVulns
  def self.dynamic_class_creation
    class_name = params[:class_name]
    
    # Dynamic class creation
    new_class = Class.new do
      eval(params[:class_body])  # VULNERABLE
    end
    Object.const_set(class_name, new_class)  # VULNERABLE
  end

  def self.monkey_patching
    class_name = params[:target_class]
    method_body = params[:method_code]
    
    # Dynamic monkey patching
    target_class = Object.const_get(class_name)  # VULNERABLE
    target_class.class_eval(method_body)  # VULNERABLE
  end
end

# Configuration-based code injection
class ConfigInjection
  def self.load_config
    config_code = File.read(params[:config_file])
    
    # Evaluating configuration files
    eval(config_code)  # VULNERABLE if config file is user-controlled
  end

  def self.plugin_loader
    plugin_name = params[:plugin]
    
    # Dynamic plugin loading
    require "plugins/#{plugin_name}"  # VULNERABLE - path traversal + code loading
    Object.const_get("#{plugin_name.camelize}Plugin").new  # VULNERABLE
  end
end

# Debugging and development vulnerabilities
class DebugController < ApplicationController
  def debug_eval
    # Debug endpoints that allow code execution
    if Rails.env.development?
      result = eval(params[:debug_code])  # VULNERABLE even in development
      render json: { result: result }
    end
  end

  def irb_session
    # Starting IRB with user context
    if params[:irb] && Rails.env.development?
      binding.irb  # INFORMATION DISCLOSURE - exposes application context
    end
  end
end

# DSL injection vulnerabilities
class DSLInjection
  def self.route_injection
    route_pattern = params[:route]
    
    # Dynamic route definition
    Rails.application.routes.draw do
      eval(route_pattern)  # VULNERABLE
    end
  end

  def self.migration_injection
    migration_code = params[:migration]
    
    # Dynamic migration execution
    ActiveRecord::Migration.class_eval(migration_code)  # VULNERABLE
  end
end