# frozen_string_literal: true

module Cd
  class ApplicationLinkPolicy < ::BasePolicy
    delegate { @subject.application }
  end
end
