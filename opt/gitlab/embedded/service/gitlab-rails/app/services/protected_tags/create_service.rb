# frozen_string_literal: true

module ProtectedTags
  class CreateService < ::BaseService
    attr_reader :protected_tag

    def execute
      raise Gitlab::Access::AccessDeniedError unless can?(current_user, :create_protected_tags, project)

      project.protected_tags.create(params)
    rescue ActiveRecord::RecordNotUnique
      # Concurrent creates can pass the uniqueness validation and hit the DB index instead
      project.protected_tags.build(params).tap do |tag|
        tag.errors.add(:name, :taken)
      end
    end
  end
end
