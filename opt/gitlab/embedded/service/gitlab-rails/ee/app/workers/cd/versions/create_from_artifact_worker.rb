# frozen_string_literal: true

module Cd
  module Versions
    class CreateFromArtifactWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      feature_category :continuous_delivery
      deduplicate :until_executed, including_scheduled: true
      concurrency_limit -> { 200 }
      idempotent!

      def self.dispatch?(event)
        case event
        when ::ContainerRegistry::ImagePushedEvent
          dispatch_image_pushed?(event)
        else
          false
        end
      end

      def self.dispatch_image_pushed?(event)
        return false unless Feature.enabled?(:ai_native_deploy, event.project)

        event.data[:tag].present? && event.data[:digest].present? && event.data[:repository].present?
      end
      private_class_method :dispatch_image_pushed?

      def handle_event(event)
        params = params_from_image_pushed(event)
        return unless params

        ::Cd::Versions::CreateFromArtifactService.new(**params).execute
      end

      private

      def params_from_image_pushed(event)
        project = Project.find_by_id(event.data[:project_id])
        return unless project

        {
          image: event.data.fetch(:image),
          source_ref: event.data.fetch(:repository),
          digest: event.data.fetch(:digest),
          organization_id: project.organization_id,
          tag: event.data[:tag]
        }
      end
    end
  end
end
