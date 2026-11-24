# frozen_string_literal: true

module Preloaders # rubocop:disable Gitlab/BoundedContexts -- matches the existing Preloaders:: convention
  module Projects
    # A setting whose project column can be NULL still runs a per-project ancestor value query.
    class CascadingSettingPreloader
      def initialize(projects, attribute)
        @projects = projects
        @attribute = attribute
      end

      def execute
        ActiveRecord::Associations::Preloader.new(records: projects, associations: [:project_setting, :group]).call

        ancestor_ids_by_project = projects.select(&:group).index_with { |p| p.group.traversal_ids.reverse }
        return if ancestor_ids_by_project.empty?

        locked_by_namespace_id = ::ProjectSetting
          .locked_namespace_settings(attribute, ancestor_ids_by_project.values.flatten.uniq)
          .index_by(&:namespace_id)

        ancestor_ids_by_project.each do |project, ancestor_ids|
          locked_ancestor = locked_by_namespace_id.values_at(*ancestor_ids).compact.min_by(&:namespace_id)
          project.project_setting.preload_locked_ancestor(attribute, locked_ancestor)
        end
      end

      private

      attr_reader :projects, :attribute
    end
  end
end
