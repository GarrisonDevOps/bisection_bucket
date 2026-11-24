# frozen_string_literal: true

module VirtualRegistries
  class DestroyLocalUpstreamsWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :virtual_registry
    urgency :low
    idempotent!
    defer_on_database_health_signal :gitlab_main, [:virtual_registries_packages_maven_local_upstreams], 5.minutes

    UPSTREAM_CLASSES = [
      ::VirtualRegistries::Packages::Maven::Local::Upstream
    ].freeze

    EVENT_MAPPING = {
      ::Projects::ProjectDeletedEvent => {
        id_field: :project_id,
        upstream_field: :local_project_id
      },
      ::Groups::GroupDeletedEvent => {
        id_field: :group_id,
        upstream_field: :local_group_id
      }
    }.freeze

    def handle_event(event)
      mapping = EVENT_MAPPING[event.class]

      return unless mapping

      id = event.data[mapping[:id_field]]

      return unless id.present?

      UPSTREAM_CLASSES.each do |klass|
        klass.where(mapping[:upstream_field] => id).find_each(&:destroy_and_sync_positions) # rubocop:disable CodeReuse/ActiveRecord -- specific code for this worker that will not be re-used
      end
    end
  end
end
