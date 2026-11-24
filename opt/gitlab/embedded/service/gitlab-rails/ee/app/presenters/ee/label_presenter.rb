# frozen_string_literal: true

module EE
  module LabelPresenter
    extend ::Gitlab::Utils::DelegatorOverride

    delegator_override :scoped_label?
    def scoped_label?
      return false unless label.scoped_label?
      return true unless context_subject

      context_subject.feature_available?(:scoped_labels)
    end
  end
end
