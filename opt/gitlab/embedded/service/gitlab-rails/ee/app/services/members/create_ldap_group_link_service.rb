# frozen_string_literal: true

module Members
  class CreateLdapGroupLinkService
    include ::Gitlab::Allowable

    def self.execute(group:, params:, current_user:)
      new(group: group, params: params, current_user: current_user).execute
    end

    def initialize(group:, params:, current_user:)
      @group = group
      @params = params
      @current_user = current_user
    end

    def execute
      ldap_group_link = group.ldap_group_links.build(params)

      if authorized?
        audit_create(ldap_group_link) if ldap_group_link.save
      else
        ldap_group_link.errors.add(:base, 'Unauthorized')
      end

      ldap_group_link
    end

    private

    attr_reader :group, :params, :current_user

    def authorized?
      can?(current_user, :create_ldap_group_link, group)
    end

    def audit_create(ldap_group_link)
      ::Gitlab::Audit::Auditor.audit(
        name: 'ldap_group_link_created',
        author: current_user,
        scope: group,
        target: group,
        message: "LDAP group link created. #{ldap_group_link.identifier_label}, " \
          "Access Level - #{ldap_group_link.human_access}, Provider - #{ldap_group_link.provider}",
        additional_details: {
          cn: ldap_group_link.cn,
          filter: ldap_group_link.filter,
          group_access: ldap_group_link.human_access,
          provider: ldap_group_link.provider
        }
      )
    end
  end
end
