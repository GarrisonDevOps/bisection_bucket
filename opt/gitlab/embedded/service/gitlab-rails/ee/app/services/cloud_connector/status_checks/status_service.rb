# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    # Runs several probes to determine whether features connected through Cloud Connector
    # are generally working. This includes checking for availability of certain network
    # endpoints, but also which license is used etc.
    class StatusService
      attr_reader :probes

      def initialize(user:, probes: nil)
        @user = user
        @probes = probes || selected_probes
      end

      def execute
        probe_results = probes.flat_map(&:execute)
        success = probe_results.all?(&:success?)
        payload = { probe_results: probe_results }

        return ServiceResponse.error(message: 'Some probes failed', payload: payload) unless success

        ServiceResponse.success(payload: payload)
      end

      private

      def selected_probes
        probe_registry = ::CloudConnector::StatusChecks::Probes::Registry.new(@user)

        if ::Gitlab::Utils.to_boolean(ENV['CLOUD_CONNECTOR_SELF_SIGN_TOKENS'])
          probe_registry.development_probes
        # We consider the instance to be using self-hosted Duo if they register a
        # self-hosted AIGW URL, or if an offline cloud license gives them no cloud
        # connector access token.
        elsif ::Gitlab::AiGateway.self_hosted_url.present? ||
            ::Gitlab::AiGateway.no_cloud_connector_token?(nil)
          probe_registry.self_hosted_probes
        elsif ::Ai::AmazonQ.connected?
          probe_registry.default_probes + probe_registry.amazon_q_probes
        else
          probe_registry.default_probes
        end
      end
    end
  end
end
