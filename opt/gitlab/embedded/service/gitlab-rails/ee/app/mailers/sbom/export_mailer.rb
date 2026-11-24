# frozen_string_literal: true

module Sbom
  class ExportMailer < ApplicationMailer
    helper ::EmailsHelper
    helper ::DependenciesHelper

    layout 'mailer'

    def completion_email(export)
      @export = export
      @expiration_days = Dependencies::DependencyListExport::EXPIRES_AFTER.in_days.to_i

      exportable = export.exportable

      group = case exportable
              when ::Project
                exportable.group
              when ::Group
                exportable
              end

      prefix = if exportable.is_a?(::Ci::Pipeline)
                 exportable.project.name
               else
                 exportable.name
               end

      mail_with_locale(
        to: export.author.notification_email_for(group),
        subject: subject(prefix, s_('Dependencies|Dependency List export'))
      )
    end
  end
end
