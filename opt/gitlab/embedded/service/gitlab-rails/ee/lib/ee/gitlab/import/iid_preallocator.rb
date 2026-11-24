# frozen_string_literal: true

module EE
  module Gitlab
    module Import
      module IidPreallocator
        extend ActiveSupport::Concern

        EE_TRACKABLE_RESOURCES = {
          epics: {
            tracker: ->(scope, iid) { ::Epic.track_group_iid!(scope, iid) },
            scope_resolver: ->(importable) { importable },
            valid_for: [:group]
          },
          iterations: {
            tracker: ->(scope, iid) { ::Iteration.track_group_iid!(scope, iid) },
            scope_resolver: ->(importable) { importable },
            valid_for: [:group]
          }
        }.freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :trackable_resources
          def trackable_resources
            super.merge(EE_TRACKABLE_RESOURCES)
          end
        end
      end
    end
  end
end
