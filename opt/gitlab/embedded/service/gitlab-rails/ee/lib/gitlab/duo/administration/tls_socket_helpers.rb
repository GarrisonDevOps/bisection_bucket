# frozen_string_literal: true

module Gitlab
  module Duo
    module Administration
      module TlsSocketHelpers
        private

        def open_tls_socket(host, port)
          [tls_socket(host, port, OpenSSL::SSL::VERIFY_PEER, cert_store), true]
        rescue OpenSSL::SSL::SSLError => e
          raise unless certificate_verification_error?(e)

          [tls_socket(host, port, OpenSSL::SSL::VERIFY_NONE, nil), false]
        end

        def certificate_verification_error?(error)
          error.message.match?(/certificate verify failed/i)
        end

        def tls_socket(host, port, verify_mode, store)
          context = OpenSSL::SSL::SSLContext.new
          context.verify_mode = verify_mode
          context.cert_store = store if store

          tcp = tcp_socket(host, port)
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, context)
          ssl.hostname = host
          ssl.sync_close = true
          ssl.connect
          ssl
        rescue StandardError
          tcp&.close
          raise
        end

        def tcp_socket(host, port)
          Socket.tcp(host, port, connect_timeout: self.class::CONNECT_TIMEOUT)
        end

        def cert_store
          store = OpenSSL::X509::Store.new
          store.set_default_paths

          ::Gitlab::X509::Certificate.load_ca_certs_bundle(::Gitlab::X509::Certificate.ca_certs_bundle).each do |cert|
            store.add_cert(cert)
          rescue OpenSSL::X509::StoreError
            next
          end

          store
        end
      end
    end
  end
end
