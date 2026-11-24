# frozen_string_literal: true

module API
  module Entities
    class LdapGroup < Grape::Entity
      expose :cn, documentation: { type: 'String', example: 'ldap-group-1' }
    end
  end
end
