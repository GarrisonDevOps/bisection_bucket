# frozen_string_literal: true

module Projects
  module AllBranchesRules
    class MergeRequestApprovalSetting
      attr_reader :project

      def initialize(project)
        @project = project
      end
    end
  end
end
