# frozen_string_literal: true

module API
  module Entities
    class RemoteMirror < Grape::Entity
      expose :id,
        documentation: { type: 'Integer', format: 'int64', example: 101486,
                         desc: 'ID of the remote mirror.' }
      expose :enabled,
        documentation: { type: 'Boolean', example: true,
                         desc: 'If `true`, the mirror is enabled.' }
      expose :safe_url, as: :url,
        documentation: { type: 'String', example: 'https://*****:*****@example.com/gitlab/example.git',
                         desc: 'Mirror URL with credentials scrubbed.' }
      expose :update_status,
        documentation: { type: 'String', example: 'finished',
                         values: ::RemoteMirror.state_machines[:update_status].states.map { |s| s.name.to_s },
                         desc: 'Status of the mirror update.' }
      expose :last_update_at,
        documentation: { type: 'DateTime', example: '2020-01-06T17:32:02.823Z',
                         desc: 'Timestamp of the last mirror attempt. ISO 8601 format.' }
      expose :last_update_started_at,
        documentation: { type: 'DateTime', example: '2020-01-06T17:32:02.823Z',
                         desc: 'Timestamp when the last mirror attempt started. ISO 8601 format.' }
      expose :last_successful_update_at,
        documentation: { type: 'DateTime', example: '2020-01-06T17:31:55.864Z',
                         desc: 'Timestamp of the last successful mirror update. ISO 8601 format.' }
      expose :last_error,
        documentation: { type: 'String', example: 'The remote mirror URL is invalid.',
                         desc: 'Error message from the last mirror attempt. `null` if successful.' }
      expose :only_protected_branches,
        documentation: { type: 'Boolean',
                         desc: 'If `true`, only protected branches are mirrored.' }
      expose :keep_divergent_refs,
        documentation: { type: 'Boolean',
                         desc: 'If `true`, divergent refs are kept when mirroring.' }
      expose :auth_method,
        documentation: { type: 'String', example: 'password',
                         desc: 'Authentication method used for the mirror.' }
      expose :ssh_known_hosts_fingerprints, as: :host_keys, using: ::API::Entities::MirrorHostKey,
        documentation: {
          type: '::API::Entities::MirrorHostKey', is_array: true,
          desc: 'Array of SSH host key fingerprints for the remote mirror. ' \
            '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/203435) in GitLab 18.4.'
        }
    end
  end
end

API::Entities::RemoteMirror.prepend_mod
