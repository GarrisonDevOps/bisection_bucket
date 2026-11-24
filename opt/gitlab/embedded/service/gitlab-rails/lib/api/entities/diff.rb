# frozen_string_literal: true

module API
  module Entities
    class Diff < Grape::Entity
      expose :diff, documentation: {
        type: 'String',
        example: '@@ -71,6 +71,8 @@\n...',
        desc: 'Diff of the changes made to the file.'
      } do |instance, options|
        options[:enable_unidiff] == true ? instance.unidiff : instance.json_safe_diff
      end
      expose :collapsed?, as: :collapsed, documentation: {
        type: 'Boolean',
        desc: 'If `true`, the file diff is excluded but can be fetched on request. ' \
          '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199633) in GitLab 18.4.'
      }
      expose :too_large?, as: :too_large, documentation: {
        type: 'Boolean',
        desc: 'If `true`, the file diff is excluded and cannot be retrieved. ' \
          '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199633) in GitLab 18.4.'
      }
      expose :new_path, documentation: {
        type: 'String', example: 'doc/update/5.4-to-6.0.md', desc: 'New path of the file.'
      }
      expose :old_path, documentation: {
        type: 'String', example: 'doc/update/5.4-to-6.0.md', desc: 'Old path of the file.'
      }
      expose :a_mode, documentation: { type: 'String', example: '100755', desc: 'Old file mode of the file.' }
      expose :b_mode, documentation: { type: 'String', example: '100644', desc: 'New file mode of the file.' }
      expose :new_file?, as: :new_file, documentation: { type: 'Boolean', desc: 'If `true`, the file was added.' }
      expose :renamed_file?, as: :renamed_file, documentation: {
        type: 'Boolean', desc: 'If `true`, the file was renamed.'
      }
      expose :deleted_file?, as: :deleted_file, documentation: {
        type: 'Boolean', desc: 'If `true`, the file was removed.'
      }
      expose :generated?, as: :generated_file, documentation: {
        type: 'Boolean', desc: 'If `true`, the file is marked as generated.'
      }
    end
  end
end
