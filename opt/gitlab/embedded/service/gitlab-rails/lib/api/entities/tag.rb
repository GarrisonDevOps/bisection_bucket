# frozen_string_literal: true

module API
  module Entities
    class Tag < Grape::Entity
      include RequestAwareEntity

      expose :name, documentation: { type: 'String', example: 'v1.0.0', desc: 'Name of the tag.' }
      expose :message, documentation: { type: 'String', example: 'Release v1.0.0', desc: 'Tag message.' }
      expose :target, documentation: {
        type: 'String', example: '2695effb5807a22ff3d138d593fd856244e155e7', desc: 'SHA that the tag points to.'
      }

      expose :commit, using: ::API::Entities::Commit,
        documentation: { type: '::API::Entities::Commit', desc: 'Commit the tag points to.' } do |repo_tag, options|
        options[:project].repository.commit(repo_tag.dereferenced_target)
      end

      expose :release, using: ::API::Entities::TagRelease,
        documentation: { type: '::API::Entities::TagRelease', desc: 'Release associated with the tag.' },
        if: ->(*) { can_read_release? } do |repo_tag, options|
        options[:releases]&.find { |r| r.tag == repo_tag.name }
      end
      expose :protected,
        documentation: { type: 'Boolean', example: true,
                         desc: 'If `true`, the tag is protected.' } do |repo_tag, options|
        ::ProtectedTag.protected?(options[:project], repo_tag.name)
      end

      expose :date, as: :created_at, documentation: {
        type: 'DateTime', example: '2023-10-12T02:16:52.000Z', desc: 'Date and time the tag was created.'
      }

      def can_read_release?
        can?(options[:current_user], :read_release, options[:project])
      end
    end
  end
end
