# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class HostProbe < BaseProbe
        extend ::Gitlab::Utils::Override

        DEFAULT_TIMEOUT_SEC = 5
        private_constant :DEFAULT_TIMEOUT_SEC

        validate :validate_connection, if: :prerequisites_for_valid_url_met?

        def initialize(service_url)
          @uri = URI.parse(service_url || '')
          @host = @uri.host
          @port = @uri.port
        end

        private

        def prerequisites_for_valid_url_met?
          return true if @host.present? && @port.present?

          url_string = @uri.to_s

          if url_string.present?
            errors.add(:base, format(_('%{service_url} is not a valid URL.'), service_url: url_string))
          else
            errors.add(:base, _('Cannot validate connection to host because the URL is empty.'))
          end

          false
        end

        override :success_message
        def success_message
          format(_('%{host} reachable.'), host: @host)
        end

        def validate_connection
          ::Gitlab::HTTP.head(@uri, timeout: DEFAULT_TIMEOUT_SEC)
        rescue StandardError => e
          errors.add(:base, connection_failed_text(e))
        end

        # Keeping this as a separate translation key since we want to eventually link this
        # to user/gitlab_duo/turn_on_off.html
        def networking_cta
          _('If you use firewalls or proxy servers, they must allow traffic to this host.')
        end

        def connection_failed_text(error)
          reason = format(_('%{host} connection failed: %{error}.'), host: @host, error: error.message)
          "#{reason}\n\n#{networking_cta}"
        end
      end
    end
  end
end
