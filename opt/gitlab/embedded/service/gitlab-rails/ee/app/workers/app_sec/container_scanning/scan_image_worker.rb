# frozen_string_literal: true

module AppSec
  module ContainerScanning
    class ScanImageWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :always
      feature_category :software_composition_analysis
      deduplicate :until_executed, including_scheduled: true
      sidekiq_options retry: 3
      idempotent!

      def handle_event(event)
        ScanImageService.new(
          image: event.data.fetch(:image),
          project_id: event.data.fetch(:project_id)
        ).execute
      end

      def self.dispatch?(event)
        project = event.project

        return false unless project
        return false unless project.licensed_feature_available?(:container_scanning_for_registry)
        return false unless project.security_setting&.container_scanning_for_registry_enabled?
        return false unless project.repository.present?

        event.data[:image].end_with?(':latest')
      end
    end
  end
end
