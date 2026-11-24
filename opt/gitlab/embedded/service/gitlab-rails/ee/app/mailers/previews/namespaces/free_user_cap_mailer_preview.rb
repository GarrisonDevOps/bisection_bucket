# frozen_string_literal: true

module Namespaces
  class FreeUserCapMailerPreview < ActionMailer::Preview
    def over_limit_email
      ::Namespaces::FreeUserCapMailer.over_limit_email(User.last, Group.last).message
    end
  end
end
