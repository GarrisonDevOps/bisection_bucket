# frozen_string_literal: true

namespace :gitlab do
  namespace :audit_events do
    namespace :streaming do
      namespace :nats do
        desc 'GitLab | Audit Events | Streaming | Ensure the NATS JetStream stream exists'
        task ensure_stream: :environment do
          result = ::AuditEvents::Streaming::NatsStreamProvisioner.new.ensure!
          puts "NATS audit streaming stream: #{result.action}"
        rescue ::Gitlab::Nats::Client::ConnectionError => e
          abort "Could not reach the NATS server: #{e.message}"
        end

        desc 'GitLab | Audit Events | Streaming | Show NATS stream info'
        task stream_info: :environment do
          info = ::AuditEvents::Streaming::NatsStreamProvisioner.new.info
          puts(info ? info.inspect : 'Stream does not exist')
        rescue ::Gitlab::Nats::Client::ConnectionError => e
          abort "Could not reach the NATS server: #{e.message}"
        end
      end
    end
  end
end
