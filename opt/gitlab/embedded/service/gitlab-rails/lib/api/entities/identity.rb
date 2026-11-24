# frozen_string_literal: true

module API
  module Entities
    class Identity < Grape::Entity
      expose :provider, documentation: {
        type: 'String', desc: 'Name of the identity provider, such as `google_oauth2` or `group_saml`.'
      }
      expose :extern_uid, documentation: { type: 'String', desc: 'ID of the user at the identity provider.' }
    end
  end
end

API::Entities::Identity.prepend_mod_with('API::Entities::Identity')
