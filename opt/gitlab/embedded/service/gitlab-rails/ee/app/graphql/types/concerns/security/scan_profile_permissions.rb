# frozen_string_literal: true

module Security
  # Security scan profiles are owned by the top-level namespace, so most of the abilities guarding
  # them are only meaningful there. Evaluating them on a subgroup or project would report `true` to
  # a subgroup maintainer who the mutations then reject, so those fields resolve against the root
  # ancestor instead of the queried resource.
  #
  # `apply_security_scan_profiles` is the exception: attaching a profile is authorized per project
  # by `Mutations::Security::ScanProfiles::Attach`, so a subgroup maintainer can legitimately apply
  # profiles without any root-level access. That field resolves against the queried resource.
  module ScanProfilePermissions
    extend ActiveSupport::Concern

    ROOT_SCOPED_ABILITIES = %i[
      read_security_scan_profiles
      create_security_scan_profiles
      update_security_scan_profiles
      delete_security_scan_profiles
    ].freeze

    included do
      ::Security::ScanProfilePermissions::ROOT_SCOPED_ABILITIES.each do |ability|
        permission_field ability,
          experiment: { milestone: '19.4' },
          description: "If `true`, the user can perform `#{ability}` on the top-level namespace " \
            'of this resource. Security scan profiles belong to the top-level namespace, so this ' \
            'ability is evaluated on the root ancestor rather than on this resource.'

        define_method(ability) do
          root_ancestor = object.root_ancestor

          return false unless root_ancestor

          Ability.allowed?(current_user, ability, root_ancestor)
        end
      end

      ability_field :apply_security_scan_profiles,
        experiment: { milestone: '19.4' },
        description: 'If `true`, the user can perform `apply_security_scan_profiles` on this ' \
          'resource. Attaching a profile is authorized per project, so this ability is evaluated ' \
          'on this resource rather than on the root ancestor.'
    end
  end
end
