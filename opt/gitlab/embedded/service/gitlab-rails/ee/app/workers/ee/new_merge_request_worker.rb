# frozen_string_literal: true

module EE
  module NewMergeRequestWorker # rubocop:disable Gitlab/BoundedContexts -- Existing module
    extend ActiveSupport::Concern

    prepended do
      include WorkerSessionStateSetter
    end
  end
end
