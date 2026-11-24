# frozen_string_literal: true

module SecretsManagement
  class GroupSecretsManagerJwt < GlobalSecretsManagerJwt
    attr_reader :group

    def initialize(group:, current_user: nil, ttl: DEFAULT_TTL)
      super(current_user: current_user, ttl: ttl)
      @group = group
    end

    private

    # The user_ claims are optional. These claims are not checked during authentication.
    # The user_claims exist to provide audit traceability context about the user performing every action in Openbao
    def resource_claims
      {
        user_id: current_user&.id.to_s,
        user_login: current_user&.username,
        user_email: current_user&.email,
        group_id: group.id.to_s,
        group_path: group.full_path,
        root_group_id: root_group_id.to_s,
        organization_id: group.organization.id.to_s,
        organization_path: group.organization.path
      }.compact
    end

    def root_group_id
      group.parent ? group.root_ancestor.id : group.id
    end
  end
end
