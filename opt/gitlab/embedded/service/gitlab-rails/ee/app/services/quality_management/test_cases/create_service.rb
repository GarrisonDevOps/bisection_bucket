# frozen_string_literal: true

module QualityManagement
  module TestCases
    class CreateService < BaseService
      PERMITTED_PARAMS = %i[title description label_ids confidential].freeze

      def initialize(project, current_user, params: {})
        super(project, current_user)

        @params = params.dup
      end

      def execute
        Issues::CreateService.new(
          container: project,
          current_user: current_user,
          params: sanitized_params.merge(work_item_type: test_case_work_item_type),
          perform_spam_check: false
        ).execute
      end

      private

      attr_reader :params

      def sanitized_params
        params.slice(*PERMITTED_PARAMS)
      end

      def test_case_work_item_type
        ::WorkItems::TypesFramework::Provider.new(project).find_by_base_type(:test_case)
      end
    end
  end
end
