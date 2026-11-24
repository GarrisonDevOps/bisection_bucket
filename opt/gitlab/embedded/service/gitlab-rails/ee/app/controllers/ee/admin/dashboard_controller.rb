# frozen_string_literal: true

module EE
  module Admin
    module DashboardController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :index
      def index
        super

        @license = License.current
      end
    end
  end
end
