# frozen_string_literal: true

module EE
  module Explore
    module ProjectsController
      extend ::Gitlab::Utils::Override
      extend ActiveSupport::Concern

      prepended do
        before_action only: [:index] do
          push_saas_feature(:group_project_permanent_deletion_confirmation)
          push_dedicated_feature(:group_project_permanent_deletion_confirmation)
        end
      end

      private

      override :preload_associations
      def preload_associations(projects)
        super.with_compliance_framework_settings
      end
    end
  end
end
