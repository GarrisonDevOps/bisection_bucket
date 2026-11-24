# frozen_string_literal: true

class ScimOauthAccessTokenEntity < Grape::Entity
  include ::API::Helpers::RelatedResourcesHelpers

  INSTANCE_SCIM_PATH = '/api/scim/v2/application'

  expose :scim_api_url do |_scim|
    expose_url(INSTANCE_SCIM_PATH)
  end

  expose :token, as: :scim_token
end
