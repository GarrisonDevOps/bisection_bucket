# frozen_string_literal: true

module WorkItems
  module OrganizationLicenseCheck
    extend ActiveSupport::Concern

    private

    def feature_available_for_resource?(resource_parent, licensed_feature)
      return false unless resource_parent

      case resource_parent
      when ::Organizations::Organization
        License.feature_available?(licensed_feature)
      else
        resource_parent.licensed_feature_available?(licensed_feature)
      end
    end
  end
end
