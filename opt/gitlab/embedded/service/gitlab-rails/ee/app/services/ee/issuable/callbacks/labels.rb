# frozen_string_literal: true

module EE
  module Issuable # rubocop:disable Gitlab/BoundedContexts -- existing module we need for looking up callback classes
    module Callbacks
      module Labels
        extend ::Gitlab::Utils::Override

        private

        override :compute_new_label_ids
        def compute_new_label_ids
          @label_ids_ordered_by_selection = params[:add_label_ids].to_a + params[:label_ids].to_a # rubocop:disable Gitlab/ModuleWithInstanceVariables -- only used within this module

          filter_mutually_exclusive_labels(super)
        end

        def filter_mutually_exclusive_labels(new_label_ids)
          return new_label_ids unless issuable.resource_parent.licensed_feature_available?(:scoped_labels)

          ScopedLabelSet.filter_mutually_exclusive(
            new_label_ids,
            existing_label_ids: issuable.label_ids,
            label_ids_ordered_by_selection: @label_ids_ordered_by_selection, # rubocop:disable Gitlab/ModuleWithInstanceVariables -- only used within this module
            lock_on_merge: issuable.supports_lock_on_merge?
          )
        end
      end
    end
  end
end
