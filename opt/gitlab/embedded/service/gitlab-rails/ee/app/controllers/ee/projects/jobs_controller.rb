# frozen_string_literal: true

module EE
  module Projects
    module JobsController
      extend ActiveSupport::Concern

      prepended do
        before_action only: [:show] do
          push_frontend_ability(
            ability: :troubleshoot_job_with_ai,
            resource: find_job_as_processable,
            user: current_user
          )
          set_application_context!
        end
      end

      def set_application_context!
        ::Gitlab::ApplicationContext.push(ai_resource: find_job_as_processable.try(:to_global_id))
      end
    end
  end
end
