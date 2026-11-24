# frozen_string_literal: true

module CustomerRelations
  module Organizations
    class BaseService < ::BaseGroupService
      private

      def allowed?
        Ability.allowed?(current_user, :admin_crm_organization, group)
      end

      def error(message)
        ServiceResponse.error(message: Array(message))
      end
    end
  end
end
