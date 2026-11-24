# frozen_string_literal: true

module Authn
  class EnterpriseUsersFinder < UsersFinder
    extend ::Gitlab::Utils::Override

    private

    override :base_scope
    def base_scope
      group = params[:enterprise_group]

      raise(ArgumentError, 'Enterprise group is required for EnterpriseUsersFinder') unless group
      raise(ArgumentError, 'Enterprise group must be a top-level group') unless group.root?
      raise Gitlab::Access::AccessDeniedError unless can_read_enterprise_users?(group)

      group.enterprise_users.order_id_desc
    end

    override :by_search
    def by_search(users)
      return users unless params[:search].present?

      users.search(params[:search], with_private_emails: true)
    end

    def can_read_enterprise_users?(group)
      Ability.allowed?(current_user, :read_enterprise_user, group)
    end
  end
end
