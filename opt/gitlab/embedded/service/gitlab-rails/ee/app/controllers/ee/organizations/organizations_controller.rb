# frozen_string_literal: true

module EE
  module Organizations
    module OrganizationsController
      extend ActiveSupport::Concern

      prepended do
        before_action(only: [:show]) do
          push_frontend_feature_flag(:artifact_registry_ui, organization)
        end
      end
    end
  end
end
