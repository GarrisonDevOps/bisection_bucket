# frozen_string_literal: true

module SecretsManagement
  class EntitlementPolicy < BasePolicy
    # Authorized on the group it was queried through, which may be a subgroup of the
    # top-level group it belongs to. A nil group is the instance-wide entitlement on
    # GitLab Self-Managed.
    delegate { @subject.queried_group || @subject.group || :global }
  end
end
