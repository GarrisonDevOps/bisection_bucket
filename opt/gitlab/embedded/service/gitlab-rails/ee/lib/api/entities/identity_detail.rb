# frozen_string_literal: true

module API
  module Entities
    class IdentityDetail < Grape::Entity
      expose :extern_uid, documentation: { type: 'String', desc: 'External UID for the user.' }
      expose :user_id, documentation: { type: 'Integer', desc: 'ID of the user.' }
      expose :active, documentation: {
        type: 'Boolean', desc: 'If `true`, the identity is active. Returned only for SCIM identities.'
      }, if: ->(identity) { identity.has_attribute?(:active) }
    end
  end
end
