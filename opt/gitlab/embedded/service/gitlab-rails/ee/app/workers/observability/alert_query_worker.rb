# frozen_string_literal: true

module Observability
  class AlertQueryWorker
    include ApplicationWorker

    data_consistency :delayed
    queue_namespace :cronjob
    feature_category :observability

    idempotent!
    worker_has_external_dependencies!

    def perform
      return unless License.feature_available?(:observability_alerts)
      return unless ::Gitlab::CurrentSettings.fetch_observability_alerts_from_cloud

      api_response = fetch_alerts
      return unless api_response

      api_response.each do |alert|
        project = Project.find_by_id(alert["project_id"])

        next unless project

        next unless Feature.enabled?(:observability_features, project.root_ancestor)
        next unless project.licensed_feature_available?(:observability)
        next unless project.project_setting.observability_alerts_enabled

        ::AlertManagement::Alert.create(
          title: alert["description"],
          project: project,
          severity: :critical,
          started_at: alert["agg_timestamp"],
          fingerprint: alert["alert_type"]
        )
      end
    end

    private

    def fetch_alerts
      access_token = CloudConnector::Tokens.get(
        unit_primitive: :observability_all,
        resource: :instance
      )

      result = Gitlab::HTTP.get(
        ::Gitlab::Observability.alerts_url,
        headers: ::CloudConnector.headers(nil).merge({
          "Authorization" => "Bearer #{access_token}"
        }),
        verify: ::Gitlab::CurrentSettings.observability_backend_ssl_verification_enabled
      )

      return [] unless result.success?

      Gitlab::Json.parse(result.body) || []
    rescue JSON::ParserError, Gitlab::HTTP_V2::BlockedUrlError
      []
    end
  end
end
