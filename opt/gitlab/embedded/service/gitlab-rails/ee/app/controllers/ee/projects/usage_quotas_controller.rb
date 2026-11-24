# frozen_string_literal: true

module EE
  module Projects
    module UsageQuotasController
      extend ActiveSupport::Concern

      prepended do
        before_action only: [:index] do
          push_frontend_feature_flag(:data_transfer_monitoring, project)
          push_frontend_feature_flag(:display_cost_factored_storage_size_on_project_pages)
        end
      end
    end
  end
end
