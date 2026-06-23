#!/usr/bin/env ruby
# passkeeper.rb
# encoding: UTF-8

require 'json'
require 'openssl'
require 'base64'
require 'fileutils'

# ANSI colors
COLORS = {
  green: "\e[92m",
  red: "\e[91m",
  yellow: "\e[93m",
  blue: "\e[94m",
  reset: "\e[0m"
}

def colorize(text, color)
  "#{COLORS[color]}#{text}#{COLORS[:reset]}"
end

DB_FILE = File.join(Dir.home, '.passkeeper.db')
SALT_LEN = 16
ITERATIONS = 100000
KEY_LEN = 32

def derive_key(password, salt)
  OpenSSL::PKCS5.pbkdf2_hmac(password, salt, ITERATIONS, KEY_LEN, 'sha256')
end

def encrypt_data(data, password, salt)
  key = derive_key(password, salt)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  iv = cipher.random_iv
  cipher.key = key
  plaintext = data.to_json
  ciphertext = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag
  # combine iv + tag + ciphertext
  combined = iv + tag + ciphertext
  Base64.strict_encode64(combined)
end

def decrypt_data(encrypted, password, salt)
  key = derive_key(password, salt)
  combined = Base64.decode64(encrypted)
  iv = combined[0, 12]
  tag = combined[12, 16]
  ciphertext = combined[28..-1]
  decipher = OpenSSL::Cipher.new('aes-256-gcm')
  decipher.decrypt
  decipher.key = key
  decipher.iv = iv
  decipher.auth_tag = tag
  plaintext = decipher.update(ciphertext) + decipher.final
  JSON.parse(plaintext)
end

def load_db
  return nil unless File.exist?(DB_FILE)
  JSON.parse(File.read(DB_FILE))
end

def save_db(db)
  File.write(DB_FILE, JSON.pretty_generate(db))
end

def main
  if ARGV.empty?
    puts colorize("Usage: passkeeper.rb <command> [args...]", :yellow)
    puts "Commands: master, add, get, list, del"
    return
  end

  cmd = ARGV[0].downcase

  if cmd == 'master'
    if ARGV.size < 2
      puts colorize("Usage: passkeeper.rb master <new_password> [old_password]", :yellow)
      return
    end
    new_pass = ARGV[1]
    db = load_db
    if db.nil?
      # New DB
      salt = OpenSSL::Random.random_bytes(SALT_LEN)
      encrypted = encrypt_data({}, new_pass, salt)
      db = { 'salt' => Base64.strict_encode64(salt), 'data' => encrypted }
      save_db(db)
      puts colorize("Master password set successfully (new database).", :green)
    else
      if ARGV.size < 3
        puts colorize("To change master password, provide old password: passkeeper.rb master <new> <old>", :yellow)
        return
      end
      old_pass = ARGV[2]
      salt = Base64.decode64(db['salt'])
      begin
        entries = decrypt_data(db['data'], old_pass, salt)
      rescue
        puts colorize("Invalid old master password.", :red)
        return
      end
      new_salt = OpenSSL::Random.random_bytes(SALT_LEN)
      new_encrypted = encrypt_data(entries, new_pass, new_salt)
      db['salt'] = Base64.strict_encode64(new_salt)
      db['data'] = new_encrypted
      save_db(db)
      puts colorize("Master password changed successfully.", :green)
    end
    return
  end

  db = load_db
  if db.nil?
    puts colorize("Database not initialized. Set master password first using 'master' command.", :red)
    return
  end
  if ARGV.size < 2
    puts colorize("Master password required.", :yellow)
    return
  end
  master_pass = ARGV[1]
  salt = Base64.decode64(db['salt'])
  begin
    entries = decrypt_data(db['data'], master_pass, salt)
  rescue
    puts colorize("Invalid master password.", :red)
    return
  end

  args = ARGV[2..-1] || []

  case cmd
  when 'add'
    if args.size < 3
      puts colorize("Usage: passkeeper.rb add <name> <login> <password> [url]", :yellow)
      return
    end
    name, login, pwd = args[0], args[1], args[2]
    url = args[3] || ''
    if entries.key?(name)
      puts colorize("Entry already exists. Use del first.", :red)
      return
    end
    entry = { 'login' => login, 'password' => pwd }
    entry['url'] = url unless url.empty?
    entries[name] = entry
    db['data'] = encrypt_data(entries, master_pass, salt)
    save_db(db)
    puts colorize("Entry '#{name}' added.", :green)

  when 'get'
    if args.empty?
      puts colorize("Usage: passkeeper.rb get <name>", :yellow)
      return
    end
    name = args[0]
    unless entries.key?(name)
      puts colorize("Entry not found.", :red)
      return
    end
    entry = entries[name]
    puts "Login: #{entry['login']}"
    puts "Password: #{entry['password']}"
    puts "URL: #{entry['url']}" if entry['url']

  when 'list'
    if entries.empty?
      puts colorize("No entries.", :yellow)
    else
      entries.keys.sort.each { |k| puts k }
    end

  when 'del'
    if args.empty?
      puts colorize("Usage: passkeeper.rb del <name>", :yellow)
      return
    end
    name = args[0]
    unless entries.key?(name)
      puts colorize("Entry not found.", :red)
      return
    end
    entries.delete(name)
    db['data'] = encrypt_data(entries, master_pass, salt)
    save_db(db)
    puts colorize("Entry '#{name}' deleted.", :green)

  else
    puts colorize("Unknown command: #{cmd}", :red)
    puts "Available: master, add, get, list, del"
  end
end

if __FILE__ == $0
  main
end
