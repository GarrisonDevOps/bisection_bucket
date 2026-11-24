# frozen_string_literal: true

module EE
  module Projects
    module PagesController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :project_params_attributes
      def project_params_attributes
        return super unless can?(current_user, :update_max_pages_size)

        super + %i[max_pages_size]
      end
    end
  end
end
