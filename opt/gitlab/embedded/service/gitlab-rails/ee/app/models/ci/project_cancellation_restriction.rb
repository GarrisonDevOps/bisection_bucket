# frozen_string_literal: true

module Ci
  class ProjectCancellationRestriction
    # Checks if cancellation restrictions are applied for pipelines and processables
    # based on the given project
    include Gitlab::Utils::StrongMemoize

    def initialize(project)
      @project = project
      @ci_settings = project&.ci_cd_settings
    end

    def maintainers_only_allowed?
      return false unless feature_available?

      @ci_settings.restrict_pipeline_cancellation_role_maintainer?
    end

    def no_one_allowed?
      return false unless feature_available?

      @ci_settings.restrict_pipeline_cancellation_role_no_one?
    end

    def role
      return unless feature_available?

      @ci_settings.restrict_pipeline_cancellation_role
    end

    def feature_available?
      return false unless @ci_settings

      @project.licensed_feature_available?(:ci_pipeline_cancellation_restrictions)
    end
    strong_memoize_attr :feature_available?
  end
end
