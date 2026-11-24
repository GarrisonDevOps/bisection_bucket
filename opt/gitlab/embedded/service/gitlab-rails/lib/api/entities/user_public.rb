# frozen_string_literal: true

module API
  module Entities
    class UserPublic < Entities::User
      expose :last_sign_in_at,
        documentation: { type: 'DateTime', example: '2015-09-03T07:24:01.670Z',
                         desc: 'Last sign-in date and time of the user in ISO 8601 format.' }
      expose :confirmed_at,
        documentation: { type: 'DateTime', example: '2015-09-03T07:24:01.670Z',
                         desc: 'Confirmation date and time of the user in ISO 8601 format.' }
      expose :last_activity_on,
        documentation: { type: 'DateTime', example: '2015-09-03T07:24:01.670Z',
                         desc: 'Last activity date of the user.' }
      expose :email, documentation: { type: 'String', example: 'john@example.com', desc: 'Email address of the user.' }
      expose :theme_id, documentation: { type: 'Integer', example: 2, desc: 'Theme ID of the user.' }
      expose :color_scheme_id, documentation: { type: 'Integer', example: 1, desc: 'Color scheme ID of the user.' }
      expose :projects_limit, documentation: { type: 'Integer', example: 10, desc: 'Project limit of the user.' }
      expose :current_sign_in_at,
        documentation: { type: 'DateTime', example: '2015-09-03T07:24:01.670Z',
                         desc: 'Current sign-in date and time of the user in ISO 8601 format. ' \
                           'Updated when the user signs in to GitLab, at most once an hour.' }
      expose :identities, using: Entities::Identity,
        documentation: { type: 'API::Entities::Identity', is_array: true,
                         desc: 'Identities associated with the user. ' \
                           'An identity with the `group_saml` provider also has `saml_provider_id`.' }
      expose :can_create_group,
        documentation: { type: 'Boolean', example: true, desc: 'If `true`, the user can create groups.' } do |user|
        Ability.allowed?(user, :create_group)
      end
      expose :can_create_project?, as: :can_create_project,
        documentation: { type: 'Boolean', example: true, desc: 'If `true`, the user can create projects.' }

      expose :two_factor_enabled?, as: :two_factor_enabled,
        documentation: { type: 'Boolean', example: true,
                         desc: 'If `true`, two-factor authentication is enabled for the user.' }

      expose :external, documentation: { type: 'Boolean', desc: 'If `true`, the user is external.' }

      expose :private_profile,
        documentation: { type: 'Boolean', example: false, desc: "If `true`, the user's profile is private." }
      expose :commit_email_or_default, as: :commit_email
      expose :preferred_language, documentation: { type: 'String', example: 'en' }
    end
  end
end

API::Entities::UserPublic.prepend_mod_with('API::Entities::UserPublic', with_descendants: true)
