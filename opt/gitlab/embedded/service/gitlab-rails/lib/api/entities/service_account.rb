# frozen_string_literal: true

module API
  module Entities
    class ServiceAccount < UserSafe
      expose :email, documentation: {
        type: 'String', example: 'service_account@example.com', desc: 'Email address of the service account.'
      }
      expose :unconfirmed_email, if: ->(service_account) { service_account.unconfirmed_email.present? },
        documentation: {
          type: 'String', example: 'updated_service_account@example.com',
          desc: 'Email address awaiting confirmation. Returned only when a confirmation is pending.'
        }
      expose :external, documentation: { type: 'Boolean', example: true }
    end
  end
end
