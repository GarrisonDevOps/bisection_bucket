# frozen_string_literal: true

module Resolvers
  class GroupMergeRequestsResolver < MergeRequestsResolver
    def self.issuable_collection_name
      'merge requests'
    end

    include GroupIssuableResolver

    alias_method :group, :object

    type Types::MergeRequestType.connection_type, null: true

    accept_assignee
    accept_reviewer
    accept_author

    before_connection_authorization do |merge_requests, current_user|
      ::Preloaders::IssuablesPreloader.new(merge_requests, current_user, project_associations).preload_all
    end

    def project
      nil
    end

    def mr_parent
      group
    end

    def no_results_possible?(args)
      group.nil? || some_argument_is_empty?(args)
    end

    private

    def unconditional_includes
      super + [{ target_project: [:group] }]
    end
  end
end
