# frozen_string_literal: true

module WorkItems
  module Statuses
    module SystemDefined
      module Templates
        class Lifecycle
          include Gitlab::Utils::StrongMemoize

          attr_accessor :namespace, :system_defined_lifecycle

          delegate :name, to: :system_defined_lifecycle

          def self.in_namespace(namespace)
            SystemDefined::Lifecycle.all.map do |system_defined_lifecycle|
              new(namespace: namespace, system_defined_lifecycle: system_defined_lifecycle)
            end
          end

          def initialize(namespace:, system_defined_lifecycle:)
            @namespace = namespace
            @system_defined_lifecycle = system_defined_lifecycle
          end

          # Templates don't need to be resolvable by Rails
          # but we need an ID so Apollo can properly handle it
          def to_global_id
            encoded_name = CGI.escape(name)
            GlobalID.parse("gid://gitlab/#{self.class.name}/#{encoded_name}")
          end

          # New lifecycles always don't have work item types attached.
          def work_item_types(_namespace = nil)
            []
          end

          def statuses
            system_defined_lifecycle.statuses.map do |system_defined_status|
              Templates::Status.new(
                lifecycle_template: self,
                system_defined_status: system_defined_status
              )
            end
          end
          strong_memoize_attr :statuses

          alias_method :ordered_statuses, :statuses # LifecycleType uses ordered_statuses

          def default_open_status
            find_status_by_name(system_defined_lifecycle.default_open_status.name)
          end
          strong_memoize_attr :default_open_status

          def default_closed_status
            find_status_by_name(system_defined_lifecycle.default_closed_status.name)
          end
          strong_memoize_attr :default_closed_status

          def default_duplicate_status
            find_status_by_name(system_defined_lifecycle.default_duplicate_status.name)
          end
          strong_memoize_attr :default_duplicate_status

          def custom_statuses_by_name
            namespace.custom_statuses.index_by(&:name)
          end
          strong_memoize_attr :custom_statuses_by_name

          private

          def find_status_by_name(name)
            statuses.find { |status| status.name == name }
          end
        end
      end
    end
  end
end
