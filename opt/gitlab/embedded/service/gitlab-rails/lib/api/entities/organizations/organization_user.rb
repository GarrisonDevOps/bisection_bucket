# frozen_string_literal: true

module API
  module Entities
    module Organizations
      class OrganizationUser < Grape::Entity
        expose :user_id, as: :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :username, documentation: { type: 'String', example: 'jane_doe' } do |organization_user|
          organization_user.user.username
        end
        expose :bot, documentation: { type: 'Boolean', example: false } do |organization_user|
          organization_user.user.bot?
        end
        expose :access_level, documentation: { type: 'String', example: 'owner' }
      end
    end
  end
end
