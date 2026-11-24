# frozen_string_literal: true

require 'logger'

GRPC_LOGGER = Logger.new(Rails.root.join('log/grpc.log'))
GRPC_LOGGER.level = ENV['GRPC_LOG_LEVEL'].presence || 'WARN'
GRPC_LOGGER.progname = 'GRPC'

module GRPC
  def self.logger
    GRPC_LOGGER
  end
end

# gRPC ships its own bundled CA roots and installs them as the default on gem
# load; that bundle can lag the system trust store. Point gRPC at the same CA
# bundle the other gRPC clients use (honors SSL_CERT_FILE/SSL_CERT_DIR), like
# config/initializers/excon.rb does for Excon.
grpc_ca_bundle = Gitlab::X509::Certificate.ca_certs_bundle

GRPC::Core::ChannelCredentials.set_default_roots_pem(grpc_ca_bundle) if grpc_ca_bundle.present?
