# frozen_string_literal: true

module Authn
  class GroupScimAuthAccessTokenEntity < Grape::Entity
    include ::API::Helpers::RelatedResourcesHelpers

    GROUP_SCIM_PATH = '/api/scim/v2/groups'

    expose :scim_api_url do |scim|
      expose_url("#{GROUP_SCIM_PATH}/#{scim.group.full_path}")
    end

    expose :token, as: :scim_token
  end
end
