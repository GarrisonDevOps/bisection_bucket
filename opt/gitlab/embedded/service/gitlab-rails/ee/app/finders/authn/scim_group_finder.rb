# frozen_string_literal: true

module Authn
  class ScimGroupFinder
    UnsupportedFilter = Class.new(StandardError)

    def search(params)
      if params[:filter].present?
        filter_groups(params[:filter])
      else
        SamlGroupLink.with_scim_group_uid
      end
    end

    private

    def filter_groups(filter)
      match = filter.to_s.match(/displayName\s+eq\s+"([^"]+)"/i) || filter.to_s.match(/displayName\s+eq\s+'([^']+)'/i)

      raise UnsupportedFilter, "Unsupported filter format: #{filter}" unless match && match[1].present?

      group_name = match[1]
      SamlGroupLink.with_scim_group_uid.by_saml_group_name(group_name)
    end
  end
end
