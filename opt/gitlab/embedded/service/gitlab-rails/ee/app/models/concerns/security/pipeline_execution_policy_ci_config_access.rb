# frozen_string_literal: true

module Security
  # Provides project-based access control for PEP CI config file includes.
  # Database columns use `bot_access` naming for backward compatibility.
  module PipelineExecutionPolicyCiConfigAccess
    extend ActiveSupport::Concern

    # Strip leading './' to normalize relative paths for consistent comparison
    LEADING_RELATIVE_PATH_PATTERN = %r{^\./}
    MAX_FILE_PATTERNS = 20
    MAX_FILE_PATTERN_LENGTH = 255

    included do
      belongs_to :pipeline_execution_policy_bot_access_group,
        class_name: 'Group',
        optional: true

      before_validation :normalize_pipeline_execution_policy_bot_access_file_patterns,
        if: :pipeline_execution_policy_bot_access_enabled?
      validate :validate_pipeline_execution_policy_bot_access_file_patterns_length,
        if: :pipeline_execution_policy_bot_access_enabled?
      validate :validate_pipeline_execution_policy_bot_access_file_patterns_format,
        if: :pipeline_execution_policy_bot_access_enabled?
      validate :validate_pipeline_execution_policy_bot_access_group,
        if: :pipeline_execution_policy_bot_access_group_id?
    end

    def allows_pipeline_execution_policy_ci_config_access?(file_path:, requesting_project:)
      return false unless valid_pipeline_execution_policy_context?(requesting_project)
      return false unless pipeline_execution_policy_bot_access_enabled?
      return false unless project_in_allowed_group?(requesting_project)

      file_pattern_matches?(file_path)
    end

    def valid_pipeline_execution_policy_context?(requesting_project)
      return false unless requesting_project

      requesting_project.security_policies.type_pipeline_execution_policy.any? ||
        requesting_project.security_policies.type_pipeline_execution_schedule_policy.any?
    end

    private

    def resolved_pipeline_execution_policy_bot_access_group
      return pipeline_execution_policy_bot_access_group if pipeline_execution_policy_bot_access_group_id.present?

      root = project.root_ancestor
      return unless root.is_a?(Group)

      root
    end

    def file_pattern_matches?(file_path)
      return false if pipeline_execution_policy_bot_access_file_patterns.empty?

      normalized_path = normalize_file_path(file_path)
      return false if normalized_path.nil?

      # Matches file path against glob pattern with:
      # - FNM_PATHNAME: wildcards don't match directory separators
      # - FNM_EXTGLOB: enables brace expansion (e.g. *.{rb,js})
      pipeline_execution_policy_bot_access_file_patterns.any? do |pattern|
        File.fnmatch?(pattern, normalized_path, File::FNM_PATHNAME | File::FNM_EXTGLOB)
      end
    end

    def project_in_allowed_group?(target_project)
      return false unless target_project

      allowed_group = resolved_pipeline_execution_policy_bot_access_group
      return false unless allowed_group

      target_project_namespace = target_project.namespace
      return false unless target_project_namespace

      target_project_namespace.self_and_ancestors.exists?(id: allowed_group.id)
    end

    def normalize_file_path(file_path)
      return if file_path.blank?

      normalized = file_path.sub(LEADING_RELATIVE_PATH_PATTERN, '')

      return if Gitlab::PathTraversal.path_traversal?(normalized)
      return if normalized.start_with?('/')

      normalized
    end

    def normalize_pipeline_execution_policy_bot_access_file_patterns
      self.pipeline_execution_policy_bot_access_file_patterns =
        pipeline_execution_policy_bot_access_file_patterns.map do |pattern|
          pattern.sub(LEADING_RELATIVE_PATH_PATTERN, '')
        end
    end

    def validate_pipeline_execution_policy_bot_access_file_patterns_length
      return unless pipeline_execution_policy_bot_access_file_patterns.length > MAX_FILE_PATTERNS

      errors.add(
        :pipeline_execution_policy_bot_access_file_patterns,
        format(_('cannot have more than %{max} file patterns'), max: MAX_FILE_PATTERNS)
      )
    end

    def validate_pipeline_execution_policy_bot_access_file_patterns_format
      pipeline_execution_policy_bot_access_file_patterns.each do |pattern|
        if pattern.blank?
          errors.add(:pipeline_execution_policy_bot_access_file_patterns, _('cannot contain empty patterns'))
        elsif pattern.length > MAX_FILE_PATTERN_LENGTH
          errors.add(
            :pipeline_execution_policy_bot_access_file_patterns,
            format(_('individual patterns cannot exceed %{max} characters'), max: MAX_FILE_PATTERN_LENGTH)
          )
        elsif pattern.start_with?('/')
          errors.add(:pipeline_execution_policy_bot_access_file_patterns, _('cannot start with /'))
        elsif Gitlab::PathTraversal.path_traversal?(pattern)
          errors.add(:pipeline_execution_policy_bot_access_file_patterns, _('cannot contain path traversal'))
        end
      end
    end

    def validate_pipeline_execution_policy_bot_access_group
      return if pipeline_execution_policy_bot_access_group_id.nil?

      unless Group.exists?(id: pipeline_execution_policy_bot_access_group_id)
        errors.add(:pipeline_execution_policy_bot_access_group, _('must be a valid group'))
        return
      end

      root = project.root_ancestor
      return unless root.is_a?(Group)

      return if root.self_and_descendants.exists?(id: pipeline_execution_policy_bot_access_group_id)

      errors.add(:pipeline_execution_policy_bot_access_group, _('must be within the project hierarchy'))
    end
  end
end
