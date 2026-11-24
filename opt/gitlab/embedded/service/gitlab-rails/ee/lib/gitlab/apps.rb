# frozen_string_literal: true

module Gitlab
  # Hardcoded GitLab Apps for Customer 0. A model replaces this list later:
  # https://gitlab.com/groups/gitlab-org/-/work_items/24271
  module Apps
    MOUNT_POINTS = %i[pipeline].freeze

    App = Data.define(:id, :title, :icon, :url, :mount_points) do
      # @return [Hash] the shape the super sidebar's nav items expect
      def to_nav_item
        { id: "gitlab_app_#{id}", title: title, icon: icon, link: url }
      end
    end

    APPS = [
      App.new(
        id: 'pipeline_visualizer', title: 'Pipeline Visualizer', icon: 'pipeline',
        url: 'https://pipeline-visualizer-gitlab-org-quality-engineeri-bcf92e4999c4df.gitlab.io/',
        mount_points: %i[pipeline]
      )
    ].freeze

    # @param namespace [Namespace, Project, nil] any resource in the hierarchy; the flag
    #   is checked against its top-level group
    # @param mount [Symbol] one of {MOUNT_POINTS}
    # @return [Array<App>]
    def self.for(namespace, mount:)
      raise ArgumentError, "unknown mount point: #{mount}" unless MOUNT_POINTS.include?(mount)
      return [] unless namespace && ::Feature.enabled?(:gitlab_apps, namespace.root_ancestor)

      APPS.select { |app| app.mount_points.include?(mount) }
    end
  end
end
