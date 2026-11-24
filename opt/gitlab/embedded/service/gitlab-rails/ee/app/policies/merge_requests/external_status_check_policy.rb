# frozen_string_literal: true

module MergeRequests
  class ExternalStatusCheckPolicy < BasePolicy
    delegate { @subject.project }
  end
end
