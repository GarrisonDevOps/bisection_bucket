# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      module RequiresIdentityVerification
        extend ActiveSupport::Concern

        private

        def raise_if_identity_verification_required!(container)
          return unless current_user.dap_identity_verification_required?(container)

          raise_resource_not_available_error!(
            s_('DuoAgentsPlatform|Identity verification is required to use GitLab Duo Agent Platform')
          )
        end
      end
    end
  end
end
