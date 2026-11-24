# frozen_string_literal: true

module Gitlab
  module Mcp
    module WorkItemIdArgument
      PATH_KEYS = %w[full_path namespace_path namespace].freeze
      CONTAINER_KEYS = (%w[project project_id group_id] + PATH_KEYS).freeze
      IID_KEY = /_iid\z/
      POSITIVE_INTEGER = /\A[1-9]\d*\z/

      class << self
        def normalize!(tool, arguments, current_user)
          return [] unless applies?(tool, arguments)

          keys = CONTAINER_KEYS & arguments.keys
          return add_container!(arguments, current_user) if keys.empty?
          return [] unless keys.one?

          key = keys.first
          target = target_key(key, arguments[key], current_user)
          value = arguments['id']

          if value.is_a?(String) && value.start_with?('gid://')
            iid = iid_from_global_id(value, target, arguments[key], current_user)
            rewrite = 'id:gid->work_item_iid'
          else
            return [] if key.in?(%w[project_id group_id])

            iid = value.to_s[POSITIVE_INTEGER]&.to_i
            rewrite = 'id->work_item_iid'
          end

          return [] unless iid

          arguments.delete('id')
          arguments['work_item_iid'] = iid
          return [rewrite] if key == target

          arguments[target] = arguments.delete(key)
          [rewrite, "#{key}->#{target}"]
        end

        private

        def applies?(tool, arguments)
          return false unless arguments.key?('id') && tool.annotations[:readOnlyHint]
          return false if arguments.key?('url') || arguments.keys.grep(IID_KEY).any?

          properties = tool.input_schema.to_h.with_indifferent_access[:properties] || {}
          properties.key?(:work_item_iid) && !properties.key?(:id)
        end

        def target_key(key, path, current_user)
          return key if key.in?(%w[project_id group_id])
          return 'project_id' if key == 'project'

          namespace = ::Namespace.without_project_namespaces.find_by_full_path(path.to_s, follow_redirects: true)
          return 'group_id' if namespace.is_a?(::Group) && Ability.allowed?(current_user, :read_group, namespace)

          'project_id'
        end

        def add_container!(arguments, current_user)
          work_item = readable_work_item(arguments['id'], current_user)
          return [] unless work_item

          target = work_item.project_id ? 'project_id' : 'group_id'
          arguments.delete('id')
          arguments['work_item_iid'] = work_item.iid
          arguments[target] = (work_item.project_id || work_item.namespace_id).to_s
          ['id:gid->work_item_iid', "id:gid->#{target}"]
        end

        def readable_work_item(value, current_user)
          return unless value.is_a?(String) && value.start_with?('gid://')

          gid = ::GlobalID.parse(value)
          work_item = gid && work_item_from(gid)
          work_item if work_item && Ability.allowed?(current_user, :read_work_item, work_item)
        end

        def iid_from_global_id(value, target, container, current_user)
          work_item = readable_work_item(value, current_user)
          return unless work_item

          parent = target == 'project_id' ? work_item.project : (work_item.namespace unless work_item.project_id)
          return unless parent

          work_item.iid if container.to_s == parent.id.to_s || container.to_s.casecmp?(parent.full_path)
        end

        def work_item_from(gid)
          ::WorkItem.find_by_id(gid.model_id) if gid.model_name.in?(%w[WorkItem Issue])
        end
      end
    end
  end
end

Gitlab::Mcp::WorkItemIdArgument.prepend_mod_with('Gitlab::Mcp::WorkItemIdArgument')
