# frozen_string_literal: true

module EE
  module Projects
    module TreeController
      extend ActiveSupport::Concern

      prepended do
        before_action do
          push_licensed_feature(:remote_development)
          push_frontend_feature_flag(:blame_agent_sessions, @project)
        end

        before_action only: [:show] do
          push_frontend_ability(ability: :read_code_navigation, resource: @project, user: current_user)
        end
      end
    end
  end
end
