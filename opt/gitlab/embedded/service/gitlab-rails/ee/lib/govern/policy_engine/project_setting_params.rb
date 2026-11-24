# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Turns one catalog setting and its value into Projects::UpdateService
    # params. The inverse of ProposedProjectSettings.
    class ProjectSettingParams
      PROJECT_SETTING = :project_setting_attributes
      CI_CD_SETTINGS = :ci_cd_settings_attributes
      PROJECT_FEATURE = :project_feature_attributes

      Target = Data.define(:column, :nest, :cast) do
        def initialize(column:, cast:, nest: nil)
          super
        end

        def params_for(value)
          converted = convert(value)
          # An unknown value must write nothing instead of falling back to private.
          return if converted.nil?

          param = { column => converted }

          nest ? { nest => param } : param
        end

        private

        def convert(value)
          case cast
          # The catalog speaks visibility names only, so raw levels may not pass.
          when :visibility_level then Gitlab::VisibilityLevel.string_options[value]
          when :feature_level then ::Featurable::STRING_OPTIONS[value]
          # An unknown enum value raises at assignment, so only catalog names may pass.
          when :squash_option then value if ::ProjectSetting.squash_options.key?(value)
          when :override_role then value if ::ProjectCiCdSetting.pipeline_variables_minimum_override_roles.key?(value)
          # Rails would cast junk to true, so only a real boolean may pass.
          when :boolean then value if [true, false].include?(value)
          end
        end
      end

      TARGETS = {
        'visibility' => Target.new(column: :visibility_level, cast: :visibility_level),
        'request_access_enabled' => Target.new(column: :request_access_enabled, cast: :boolean),
        'only_allow_merge_if_pipeline_succeeds' =>
          Target.new(column: :only_allow_merge_if_pipeline_succeeds, cast: :boolean),
        'only_allow_merge_if_all_discussions_are_resolved' =>
          Target.new(column: :only_allow_merge_if_all_discussions_are_resolved, cast: :boolean),
        'remove_source_branch_after_merge' =>
          Target.new(column: :remove_source_branch_after_merge, cast: :boolean),
        'squash_option' => Target.new(column: :squash_option, nest: PROJECT_SETTING, cast: :squash_option),
        'keep_latest_artifact' => Target.new(column: :keep_latest_artifact, nest: CI_CD_SETTINGS, cast: :boolean),
        'allow_fork_pipelines_to_run_in_parent_project' =>
          Target.new(column: :allow_fork_pipelines_to_run_in_parent_project, nest: CI_CD_SETTINGS, cast: :boolean),
        # Only the top-level param runs the permission check for the override role.
        'pipeline_variables_minimum_override_role' =>
          Target.new(column: :ci_pipeline_variables_minimum_override_role, cast: :override_role),
        'merge_requests_access_level' =>
          Target.new(column: :merge_requests_access_level, nest: PROJECT_FEATURE, cast: :feature_level),
        'builds_access_level' =>
          Target.new(column: :builds_access_level, nest: PROJECT_FEATURE, cast: :feature_level),
        'forking_access_level' =>
          Target.new(column: :forking_access_level, nest: PROJECT_FEATURE, cast: :feature_level)
      }.freeze

      # @return [Hash, nil] the update params, or nil for a setting or value
      #   this cannot write.
      def self.for(setting, value)
        approval = ApprovalSettings.by_setting(setting)
        return approval_params(approval, value) if approval

        TARGETS[setting]&.params_for(value)
      end

      # The approval cast coerces junk to a boolean, so only a real boolean may pass.
      def self.approval_params(approval, value)
        return unless [true, false].include?(value)

        { approval.column => approval.convert(value) }
      end
      private_class_method :approval_params
    end
  end
end
