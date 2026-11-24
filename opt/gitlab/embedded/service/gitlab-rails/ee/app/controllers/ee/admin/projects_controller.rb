# frozen_string_literal: true

module EE
  module Admin
    module ProjectsController
      extend ActiveSupport::Concern

      prepended do
        authorize! :read_admin_projects, only: %i[index show]

        before_action :limited_actions_message!, only: :show
        before_action only: [:index] do
          push_saas_feature(:group_project_permanent_deletion_confirmation)
          push_dedicated_feature(:group_project_permanent_deletion_confirmation)
        end
      end
    end
  end
end
