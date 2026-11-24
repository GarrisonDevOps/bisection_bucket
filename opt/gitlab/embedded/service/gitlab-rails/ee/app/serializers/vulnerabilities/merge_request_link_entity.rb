# frozen_string_literal: true

module Vulnerabilities
  class MergeRequestLinkEntity < Grape::Entity
    include RequestAwareEntity

    class AuthorEntity < UserEntity
      expose :human?, as: :human, documentation: { type: 'boolean', example: true }
    end

    expose :merge_request_iid, if: ->(link, _) { link.merge_request.present? } do |merge_request_link|
      merge_request_link.merge_request.iid
    end

    expose :merge_request_path, if: ->(_, _) { can_read_merge_request? } do |merge_request_link|
      project_merge_request_path(merge_request_link.vulnerability.project, merge_request_link.merge_request)
    end

    expose :state, if: ->(link, _) { link.merge_request.present? } do |merge_request_link|
      merge_request_link.merge_request.state
    end

    expose :author, using: AuthorEntity, if: ->(link, _) { link.merge_request.present? }
    expose :created_at

    alias_method :merge_request_link, :object

    private

    def can_read_merge_request?
      merge_request_link.merge_request.present? &&
        can?(current_user, :read_merge_request, merge_request_link.merge_request)
    end

    # The request can be either nil or an instance of `EntityRequest`.
    # If the latter, it may or may not respond to `current_user` so that's
    # why we need to have the following guard clause.
    def current_user
      request.current_user if request.respond_to?(:current_user)
    end
  end
end
