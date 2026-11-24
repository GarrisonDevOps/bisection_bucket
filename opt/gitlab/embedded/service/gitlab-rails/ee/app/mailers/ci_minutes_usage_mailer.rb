# frozen_string_literal: true

class CiMinutesUsageMailer < ApplicationMailer
  include ActionView::Helpers::NumberHelper

  helper EmailsHelper
  helper NamespacesHelper

  layout 'mailer'

  def notify(namespace, recipients)
    @namespace = namespace

    mail_with_locale(
      bcc: recipients,
      subject: "Action required: There are no remaining compute minutes for #{@namespace.name}"
    )
  end

  def notify_limit(namespace, recipients, current_balance, total, percentage, stage_percentage)
    @namespace = namespace
    @current_balance = number_with_delimiter(current_balance)
    @total = number_with_delimiter(total)
    @percentage = percentage.round

    mail_with_locale(
      bcc: recipients,
      subject: "Action required: Less than #{stage_percentage}% " \
               "of compute minutes remain for #{@namespace.name}"
    )
  end
end
