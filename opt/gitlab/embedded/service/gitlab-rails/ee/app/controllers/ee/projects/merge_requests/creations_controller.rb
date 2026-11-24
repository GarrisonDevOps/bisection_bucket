# frozen_string_literal: true

module EE
  module Projects
    module MergeRequests
      module CreationsController
        extend ActiveSupport::Concern

        prepended do
          before_action :disable_query_limiting, only: [:create]
          before_action :check_for_saml_authorization, only: [:new]
          after_action :display_duo_seat_warning, only: [:create]
        end

        private

        def check_for_saml_authorization
          groups = target_groups(get_target_projects)
          return if groups.empty?

          saml_groups(groups, current_user)
        end

        def source_project
          @project
        end

        def disable_query_limiting
          ::Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/20801')
        end
      end
    end
  end
end
