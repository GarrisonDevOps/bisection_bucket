# frozen_string_literal: true

module GitlabSubscriptions
  # Owning a group doesn't grant access to Organization billing, so group Owners who
  # can't read the Organization credits page see a message instead of a 404.
  module OrganizationCreditsRedirect
    extend ActiveSupport::Concern

    private

    # @return [void]
    def redirect_organization_billed_group!
      return unless group.organization_billing_namespace

      organization_path = GitlabSubscriptions::OrganizationCreditsDashboard.path_for(group, current_user)

      if organization_path
        redirect_to organization_path
      else
        render 'shared/gitlab_credits/managed_by_organization'
      end

      nil
    end
  end
end
