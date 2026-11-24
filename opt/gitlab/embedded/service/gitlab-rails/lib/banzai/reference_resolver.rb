# frozen_string_literal: true

module Banzai
  class ReferenceResolver
    include Gitlab::Utils::StrongMemoize

    def self.from_context(context)
      new(project: context[:project], group: context[:group], author: context[:author])
    end

    def initialize(project: nil, group: nil, author: nil)
      @project = project
      @group = group
      @author = author
    end

    def organization
      (@project || @group)&.organization ||
        @author&.organizations&.first ||
        Organizations::Organization.first
    end
    strong_memoize_attr :organization

    def projects
      Project.all
    end

    def namespaces
      Namespace.all
    end

    def groups
      Group.all
    end

    def users
      User.all
    end

    def routes_by_paths(paths)
      Route.by_paths(paths)
    end

    def organization_user_details
      Organizations::OrganizationUserDetail.for_references.in_organization(organization)
    end

    def cache_key
      nil
    end

    def request_store_key(name)
      [name, cache_key]
    end
  end
end
