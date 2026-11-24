# frozen_string_literal: true

module API
  module Entities
    class SSHKeyWithUser < Entities::SSHKey
      expose :user, using: ::API::Entities::UserPublic,
        documentation: { type: 'API::Entities::UserPublic', desc: 'User associated with the key.' }
    end
  end
end
