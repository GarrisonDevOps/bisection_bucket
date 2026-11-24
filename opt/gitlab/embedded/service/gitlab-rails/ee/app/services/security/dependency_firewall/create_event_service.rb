# frozen_string_literal: true

module Security
  module DependencyFirewall
    class CreateEventService < BaseService
      include Gitlab::InternalEventsTracking

      PACKAGE_DOWNLOAD = 1
      PACKAGE_UPLOAD = 2
      CONTAINER_PULL = 3
      CONTAINER_PUSH = 4
      PACKAGE_FORWARDED = 5

      INTERNAL_EVENTS_NAMES = {
        'pull_package_package' => 'collect_dependency_firewall_metrics_on_package_download_from_package_registry',
        'push_package_package' => 'collect_dependency_firewall_metrics_on_package_upload_to_package_registry',
        'pull_container_package' => 'collect_dependency_firewall_metrics_on_image_pull_from_container_registry',
        'push_container_package' => 'collect_dependency_firewall_metrics_on_image_push_to_container_registry',
        'forwarded_pull_package' =>
          'collect_dependency_firewall_metrics_on_forwarded_package_download_from_package_registry'
      }.freeze

      def execute
        event_key = determine_event_name
        return unless event_key && INTERNAL_EVENTS_NAMES.key?(event_key)

        # current_user is a DeployToken in CI_JOB_TOKEN / deploy-token contexts and
        # Gitlab::Tracking::EventValidator rejects anything that is not a User.
        # Follow the established convention (see app/services/packages/create_event_service.rb):
        # only forward :user when it really is a User; the tracker treats nil as anonymous.
        user = current_user if current_user.is_a?(User)

        track_internal_event(
          INTERNAL_EVENTS_NAMES[event_key],
          user: user,
          project: project,
          namespace: params[:namespace],
          additional_properties: build_additional_properties
        )
      end

      private

      def determine_event_name
        operation = params[:operation]

        case operation
        when PACKAGE_DOWNLOAD
          'pull_package_package'
        when PACKAGE_UPLOAD
          'push_package_package'
        when CONTAINER_PULL
          'pull_container_package'
        when CONTAINER_PUSH
          'push_container_package'
        when PACKAGE_FORWARDED
          'forwarded_pull_package'
        else
          Gitlab::AppLogger.warn(
            "DependencyFirewall: unknown operation #{operation.inspect}, event will not be tracked"
          )
          nil
        end
      end

      def build_additional_properties
        properties = {
          label: outcome_label(params[:outcome]),
          property: params[:cache_hit] ? "1" : "0",
          value: params[:runtime_ms],
          purl: params[:purl]
        }
        # An absent key rather than a null value: see Security::DependencyFirewall::SessionId.
        properties[:session_id] = params[:session_id] if params[:session_id]

        properties
      end

      def outcome_label(outcome)
        case outcome
        when EnforcementService::SUCCESS_ALLOWED then 'allowed'
        when EnforcementService::SUCCESS_BLOCKED then 'blocked-license'
        when EnforcementService::SUCCESS_WARNING then 'warn-license'
        else raise ArgumentError, "DependencyFirewall: unknown outcome #{outcome.inspect}"
        end
      end
    end
  end
end
