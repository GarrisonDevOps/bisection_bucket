# frozen_string_literal: true

module EE
  module PagesDomain
    extend ActiveSupport::Concern

    prepended do
      scope :with_logging_info, -> { includes(project: [:route, { namespace: :gitlab_subscription }]) }
      validate :domain_deny_list_exclusion

      def domain_deny_list_exclusion
        return unless domain
        return unless ::Gitlab::Access::ReservedDomains::ALL.include?(domain.downcase)

        errors.add(:domain, format(_("You cannot verify %{value} because it is a popular public email domain."),
          value: domain))
      end
    end

    def root_group
      return unless project
      return unless project.root_namespace.group_namespace?

      project.root_namespace
    end
  end
end
