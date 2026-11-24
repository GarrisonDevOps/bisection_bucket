# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Maps Projects::UpdateService params to the catalog keys and values the
    # settings context reports.
    class ProposedProjectSettings
      BOOLEAN = ActiveModel::Type::Boolean.new

      # A form sends every value as a string, so "20" and "1" arrive where the
      # context reports 20 and true.
      INTEGER_STRING = /\A-?\d+\z/

      PROJECT_BOOLEAN_COLUMNS = %w[
        request_access_enabled
        only_allow_merge_if_pipeline_succeeds
        only_allow_merge_if_all_discussions_are_resolved
        remove_source_branch_after_merge
      ].freeze

      CI_CD_BOOLEANS = %w[keep_latest_artifact allow_fork_pipelines_to_run_in_parent_project].freeze
      FEATURE_LEVELS = %w[merge_requests_access_level builds_access_level forking_access_level].freeze

      # Project delegates these to its associations, so the REST API and the
      # CI/CD settings mutation and controller send them as top-level params.
      CI_CD_DELEGATES = {
        'keep_latest_artifact' => 'keep_latest_artifact',
        'ci_allow_fork_pipelines_to_run_in_parent_project' => 'allow_fork_pipelines_to_run_in_parent_project',
        'ci_pipeline_variables_minimum_override_role' => 'pipeline_variables_minimum_override_role'
      }.freeze
      FEATURE_ENABLED_FLAGS = {
        'builds_enabled' => 'builds_access_level',
        'merge_requests_enabled' => 'merge_requests_access_level'
      }.freeze

      def self.from_params(params)
        new(params).to_h
      end

      # The unfiltered view, so a strong-parameter slice never hides a governed key.
      def initialize(params)
        @params = (params.try(:to_unsafe_h) || params || {}).with_indifferent_access
      end

      # @return [Hash<String, Object>] catalog key => proposed value, for every
      #   governed key the params carry, changed or not.
      def to_h
        proposed = {}

        add_visibility(proposed)
        add_project_columns(proposed)
        add_approval_columns(proposed)
        proposed.merge!(
          squash_option(params),
          ci_cd(params.slice(*CI_CD_DELEGATES.keys).transform_keys { |key| CI_CD_DELEGATES[key] }),
          feature_enabled_flags(params),
          feature_levels(params)
        )
        add_nested(proposed, :project_setting_attributes) { |attrs| squash_option(attrs) }
        add_nested(proposed, :ci_cd_settings_attributes) { |attrs| ci_cd(attrs) }
        add_nested(proposed, :project_feature_attributes) { |attrs| feature_levels(attrs) }

        proposed
      end

      private

      attr_reader :params

      def as_integer(value)
        INTEGER_STRING.match?(value.to_s) ? value.to_i : value
      end

      # Either param can carry a level or a name, and the context reports the name.
      def add_visibility(proposed)
        return unless params.key?(:visibility_level) || params.key?(:visibility)

        raw = params[:visibility_level] || params[:visibility]
        level = Gitlab::VisibilityLevel.level_value(as_integer(raw))

        proposed['visibility'] = Gitlab::VisibilityLevel.string_level(level)
      end

      def add_project_columns(proposed)
        PROJECT_BOOLEAN_COLUMNS.each do |column|
          proposed[column] = BOOLEAN.cast(params[column]) if params.key?(column)
        end
      end

      def add_approval_columns(proposed)
        ApprovalSettings::ENTRIES.each do |entry|
          next unless params.key?(entry.column)

          proposed[entry.setting] = entry.convert(params[entry.column])
        end
      end

      def add_nested(proposed, attributes_key)
        attrs = params[attributes_key].try(:with_indifferent_access)
        return unless attrs

        proposed.merge!(yield(attrs))
      end

      # A stored enum arrives as its number, and the catalog speaks its name.
      def squash_option(attrs)
        return {} unless attrs.key?(:squash_option)

        raw = attrs[:squash_option]
        name = ProjectSetting.squash_options.key(as_integer(raw)) || raw

        { 'squash_option' => name.to_s }
      end

      def ci_cd(attrs)
        proposed = {}

        CI_CD_BOOLEANS.each do |column|
          proposed[column] = BOOLEAN.cast(attrs[column]) if attrs.key?(column)
        end

        if attrs.key?(:pipeline_variables_minimum_override_role)
          role = attrs[:pipeline_variables_minimum_override_role]
          proposed['pipeline_variables_minimum_override_role'] =
            (::ProjectCiCdSetting::PIPELINE_VARIABLES_OVERRIDE_ROLES.key(as_integer(role)) || role).to_s
        end

        proposed
      end

      # A boolean maps to enabled or disabled, as ProjectFeaturesCompatibility writes it.
      def feature_enabled_flags(attrs)
        FEATURE_ENABLED_FLAGS.each_with_object({}) do |(flag, column), proposed|
          enabled = Gitlab::Utils.to_boolean(attrs[flag]) if attrs.key?(flag)
          next if enabled.nil?

          proposed[column] = enabled ? 'enabled' : 'disabled'
        end
      end

      def feature_levels(attrs)
        FEATURE_LEVELS.each_with_object({}) do |column, proposed|
          next unless attrs.key?(column)

          raw = attrs[column]
          proposed[column] = (::Featurable::STRING_OPTIONS.key(as_integer(raw)) || raw).to_s
        end
      end
    end
  end
end
