# frozen_string_literal: true

module EE
  module Projects
    module CommitController
      extend ActiveSupport::Concern

      prepended do
        before_action only: [:show] do
          set_application_context!
        end
      end

      def set_application_context!
        ::Gitlab::ApplicationContext.push(ai_resource: commit.try(:to_global_id))
      end
    end
  end
end
