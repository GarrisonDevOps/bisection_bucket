# frozen_string_literal: true

module API
  module Entities
    class UserAssociationsCount < Grape::Entity
      expose :groups_count, documentation: { type: 'Integer', example: 1 } do |user|
        user.groups.size
      end

      expose :projects_count, documentation: { type: 'Integer', example: 1 } do |user|
        user.projects.size
      end

      expose :issues_count, documentation: { type: 'Integer', example: 1 } do |user|
        user.issues.size
      end

      expose :merge_requests_count, documentation: { type: 'Integer', example: 1 } do |user|
        user.merge_requests.size
      end
    end
  end
end
