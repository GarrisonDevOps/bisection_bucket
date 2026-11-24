# frozen_string_literal: true

module EE
  module Admin
    module JobsController
      extend ActiveSupport::Concern

      prepended do
        authorize! :read_admin_cicd, only: [:index]
      end
    end
  end
end
