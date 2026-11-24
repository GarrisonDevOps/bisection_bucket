# frozen_string_literal: true

# Don't overwrite any existing keys.
return if CloudConnector::Keys.any?

puts Rainbow("Generate Cloud Connector signing keys").green
CloudConnector::Keys.create!(secret_key: OpenSSL::PKey::RSA.new(2048).to_pem)
puts Rainbow("\nOK").green
