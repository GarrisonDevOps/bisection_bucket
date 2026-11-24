# frozen_string_literal: true

module EE
  module Dashboard
    module GroupsController
      extend ActiveSupport::Concern

      prepended do
        before_action only: [:index] do
          push_saas_feature(:group_project_permanent_deletion_confirmation)
          push_dedicated_feature(:group_project_permanent_deletion_confirmation)
        end
      end
    end
  end
end
