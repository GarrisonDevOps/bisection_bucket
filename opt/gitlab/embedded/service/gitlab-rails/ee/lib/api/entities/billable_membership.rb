# frozen_string_literal: true

module API
  module Entities
    class BillableMembership < Grape::Entity
      include RequestAwareEntity

      expose :id, documentation: { type: 'Integer' }
      expose :source_id, documentation: { type: 'Integer' }
      expose :source_full_name, documentation: { type: 'String' } do |member|
        member.source.full_name
      end
      expose :source_members_url, documentation: { type: 'String' } do |member|
        source_members_url(member)
      end
      expose :created_at, documentation: { type: 'DateTime' }
      expose :expires_at, documentation: { type: 'Date' }
      expose :access_level, documentation: { type: 'Hash' } do
        expose :human_access, as: :string_value, documentation: { type: 'String' }
        # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
        expose :access_level, as: :integer_value, documentation: { type: 'Integer' }
        # rubocop:enable API/AccessLevelStringType
        expose :custom_role, documentation: { type: 'Hash' } do |member|
          { id: member.member_role.id, name: member.member_role.name } if member.member_role.present?
        end
      end
    end
  end
end
