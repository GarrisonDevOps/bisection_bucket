# frozen_string_literal: true

module API
  module Helpers
    module RemoteMirrorsHelpers
      extend ActiveSupport::Concern
      extend Grape::API::Helpers

      params :mirror_branches_setting_ce do
        optional :only_protected_branches, type: Boolean, desc: 'If `true`, only protected branches are mirrored.'
      end

      params :mirror_branches_setting_ee do
      end

      params :mirror_branches_setting do
        use :mirror_branches_setting_ce
        use :mirror_branches_setting_ee
      end

      params :host_key_params do
        optional :host_keys, type: Array[String],
          desc: 'SSH host keys in bare format, such as `ssh-ed25519 AAAA...`, or full `known_hosts` format, such as ' \
            '`hostname ssh-ed25519 AAAA...`. Bare keys use the hostname from the mirror URL. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203435) in GitLab 18.4.'
      end
    end
  end
end

API::Helpers::RemoteMirrorsHelpers.prepend_mod
