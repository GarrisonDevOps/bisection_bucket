# frozen_string_literal: true

module Ai
  module DapFactory
    # The Review stage starts from merge request events, so it needs automatic Duo Code Review on.
    class AutoReview
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :project

      def initialize(project)
        @project = project
      end

      def available?
        ::Gitlab::Duo::CodeReview.available?(project)
      end
      strong_memoize_attr :available?

      def enabled?
        available? && project.auto_duo_code_review_enabled
      end

      def decisions_enabled?
        ::Gitlab::Duo::CodeReview.decisions_settings_available?(project) && project.duo_code_review_decisions_enabled
      end

      def locked?
        project.project_setting.auto_duo_code_review_enabled_locked?
      end
    end
  end
end
