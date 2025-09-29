# SQL Injection Test Cases

class SqlInjectionController < ApplicationController
  def vulnerable_queries
    user_id = params[:user_id]
    search_term = params[:search]
    
    # Direct SQL injection vulnerabilities
    User.where("id = #{user_id}")  # VULNERABLE
    User.find_by_sql("SELECT * FROM users WHERE name = '#{search_term}'")  # VULNERABLE
    
    # ActiveRecord query methods with string interpolation
    User.where("name LIKE '%#{search_term}%'")  # VULNERABLE
    User.joins("JOIN posts ON posts.user_id = #{user_id}")  # VULNERABLE
    
    # Raw SQL execution
    ActiveRecord::Base.connection.execute("DELETE FROM users WHERE id = #{user_id}")  # VULNERABLE
    ActiveRecord::Base.connection.select_all("SELECT * FROM users WHERE active = #{params[:active]}")  # VULNERABLE
  end

  def order_by_injection
    sort_column = params[:sort]
    sort_direction = params[:dir]
    
    # Order by injection
    User.order("#{sort_column} #{sort_direction}")  # VULNERABLE
    Post.reorder("#{sort_column}")  # VULNERABLE
  end

  def group_having_injection
    group_field = params[:group_by]
    having_clause = params[:having]
    
    # Group and having clause injection
    User.group("#{group_field}")  # VULNERABLE
    User.group(:department).having("count(*) > #{having_clause}")  # VULNERABLE
  end

  def safe_queries
    user_id = params[:user_id]
    search_term = params[:search]
    
    # Safe parameterized queries
    User.where("id = ?", user_id)  # SAFE
    User.where(id: user_id)  # SAFE
    User.where("name LIKE ?", "%#{search_term}%")  # SAFE
    
    # Safe with sanitization
    safe_search = ActiveRecord::Base.sanitize_sql_like(search_term)
    User.where("name LIKE ?", "%#{safe_search}%")  # SAFE
  end

  def complex_vulnerable
    conditions = []
    values = []
    
    # Building dynamic queries unsafely
    if params[:name]
      conditions << "name = '#{params[:name]}'"  # VULNERABLE
    end
    
    if params[:email]
      conditions << "email LIKE '%#{params[:email]}%'"  # VULNERABLE  
    end
    
    User.where(conditions.join(" AND "))
  end

  def nosql_injection
    search_params = params[:search]
    
    # MongoDB injection patterns (if using Mongoid)
    User.where(eval(search_params))  # VULNERABLE - code injection via NoSQL
    User.where(search_params)  # POTENTIALLY VULNERABLE if search_params is a hash with operators
  end
end

# Sequel ORM patterns
class SequelSqlInjection
  def vulnerable_sequel
    user_input = params[:input]
    
    # Sequel injection patterns
    DB["SELECT * FROM users WHERE name = '#{user_input}'"]  # VULNERABLE
    DB[:users].where("active = #{user_input}")  # VULNERABLE
  end
  
  def safe_sequel
    user_input = params[:input]
    
    # Safe Sequel patterns
    DB[:users].where(name: user_input)  # SAFE
    DB["SELECT * FROM users WHERE name = ?", user_input]  # SAFE
  end
end

# Data Mapper patterns
class DataMapperSqlInjection
  def vulnerable_dm
    search = params[:search]
    
    # DataMapper injection
    User.all(:conditions => ["name = '#{search}'"])  # VULNERABLE
  end
end