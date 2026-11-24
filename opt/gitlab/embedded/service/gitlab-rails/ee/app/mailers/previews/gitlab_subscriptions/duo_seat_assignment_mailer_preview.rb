# frozen_string_literal: true

module GitlabSubscriptions
  class DuoSeatAssignmentMailerPreview < ActionMailer::Preview
    def duo_pro_email
      ::GitlabSubscriptions::DuoSeatAssignmentMailer.duo_pro_email(User.last).message
    end

    def duo_enterprise_email
      ::GitlabSubscriptions::DuoSeatAssignmentMailer.duo_enterprise_email(User.last).message
    end
  end
end
