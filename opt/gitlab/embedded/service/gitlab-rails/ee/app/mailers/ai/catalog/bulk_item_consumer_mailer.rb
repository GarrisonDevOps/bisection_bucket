# frozen_string_literal: true

module Ai
  module Catalog
    class BulkItemConsumerMailer < ApplicationMailer
      helper EmailsHelper

      layout 'mailer'

      helper_method :item_url, :total_count

      def bulk_create_result_email(user:, item:, successful_count:, failures:, warnings: [])
        @user = user
        @item = item
        @successful_count = successful_count
        @failures = failures
        @warnings = warnings
        @has_failures = failures.present?
        @has_warnings = warnings.present?
        @all_failed = @has_failures && successful_count == 0
        load_failed_projects
        load_warned_projects

        mail(
          to: user.notification_email_or_default,
          subject: email_subject
        )
      end

      private

      def load_failed_projects
        return if @failures.blank?

        project_ids = @failures.pluck(:project_id) # rubocop:disable CodeReuse/ActiveRecord -- Plucking from an array, not an AR relation
        projects_by_id = Project.id_in(project_ids).inc_routes.index_by(&:id)

        @failures.each do |failure|
          failure[:project] = projects_by_id[failure[:project_id]]
        end

        @failures.select! { |f| f[:project].present? }
      end

      def load_warned_projects
        return if @warnings.blank?

        project_ids = @warnings.pluck(:project_id) # rubocop:disable CodeReuse/ActiveRecord -- Plucking from an array, not an AR relation
        projects_by_id = Project.id_in(project_ids).inc_routes.index_by(&:id)

        @warnings.each do |warning|
          warning[:project] = projects_by_id[warning[:project_id]]
        end

        @warnings.select! { |w| w[:project].present? }
      end

      def item_url
        Gitlab::UrlBuilder.build(@item)
      end

      def total_count
        @successful_count + @failures.size
      end

      def email_subject
        if @all_failed
          format(s_('AICatalog|Bulk enablement failed for %{item_name}'), item_name: @item.name)
        elsif @has_failures
          format(s_('AICatalog|Bulk enablement completed with errors for %{item_name}'), item_name: @item.name)
        else
          format(s_('AICatalog|Bulk enablement completed for %{item_name}'), item_name: @item.name)
        end
      end
    end
  end
end
