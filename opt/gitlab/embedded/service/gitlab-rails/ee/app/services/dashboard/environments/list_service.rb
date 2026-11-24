# frozen_string_literal: true

module Dashboard
  module Environments
    class ListService
      attr_reader :user, :organization

      def initialize(user, organization: nil)
        @user = user
        @organization = organization
      end

      def execute
        ::Dashboard::Projects::ListService
          .new(user, feature: :operations_dashboard, organization: organization)
          .execute(user.ops_dashboard_projects)
      end
    end
  end
end
